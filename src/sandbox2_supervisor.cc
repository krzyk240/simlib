#include "sandbox2_supervisor.hh"
#include "sandbox2_tracee.hh"
#include "simlib/debug.hh"
#include "simlib/file_contents.hh"
#include "simlib/file_descriptor.hh"
#include "simlib/sandbox2.hh"
#include "simlib/string_view.hh"
#include "simlib/syscalls.hh"
#include "simlib/utilities.hh"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <map>
#include <optional>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <unistd.h>

using std::chrono_literals::operator""ns;

namespace {

constexpr DebugLogger<true, true> debuglog{};

struct Supervisor {
    FileDescriptor error_fd;

    // The process with pid 1 (init process) in the new user namespace
    struct Tracee {
        // State automaton:
        //                          process died, but supervisor did not kill it
        //                           ,--------------------------------------.
        //                          /            waitid_tracee()            |
        // --> NOT_STARTED         /                                        v
        //          `--------> KILLABLE ----------> UNWAITED -----------> WAITED
        //        run_tracee()         kill_tracee()        waitid_tracee()
        enum State {
            NOT_STARTED,
            KILLABLE, // started but neither killed nor waited
            UNWAITED, // killed but not waited
            WAITED, // dead and waited
        } state = NOT_STARTED;
        pid_t pid = 0;
        FileDescriptor pidfd;
        siginfo_t si{};
    } tracee;

    // Process hierarchy looks as follows:
    // caller of sandbox::execute()
    // `--> supervisor process
    //      `---> tracee

    std::chrono::nanoseconds total_cpu_time{0};
    uint64_t total_vm_peak = 0; // in bytes

    explicit Supervisor(FileDescriptor error_fd) noexcept
    : error_fd{std::move(error_fd)} {}

    Supervisor(const Supervisor&) = delete;
    Supervisor(Supervisor&&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;
    Supervisor& operator=(Supervisor&&) = delete;
    ~Supervisor() = default;

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] auto kill_tracee() noexcept {
        assert(tracee.state == Tracee::KILLABLE);
        debuglog.verbose("kill(tracee)");
        auto res = syscalls::pidfd_send_signal(tracee.pidfd, SIGKILL, nullptr, 0);
        tracee.state = Tracee::UNWAITED;
        return res;
    }

    [[nodiscard]] auto waitid_tracee() noexcept {
        assert(is_one_of(tracee.state, Tracee::KILLABLE, Tracee::UNWAITED));
        auto res = syscalls::waitid(P_PIDFD, tracee.pidfd, &tracee.si, WEXITED, nullptr);
        debuglog.verbose(
            "waitid(tracee, {pid: ", tracee.si.si_pid, ", signo: ", tracee.si.si_signo,
            ", code: ", tracee.si.si_code, ", status: ", tracee.si.si_status, "})");
        tracee.state = Tracee::WAITED;
        return res;
    }

    template <class... Args>
    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[noreturn]] void die(const Args&... args) noexcept {
        static_assert(sizeof...(Args) > 0, "error message cannot be empty");
        auto die_impl = [this](auto const&... args) noexcept {
            for (auto msg : {StringView{args}...}) {
                if (not msg.empty()) {
                    (void)write_all(error_fd, msg);
                }
            }
            _exit(42);
        };
        if (tracee.state == Tracee::KILLABLE and kill_tracee() and errno != ESRCH) {
            // ESRCH may appear if the process has already died
            die_impl(
                "pidfd_send_signal(tracee, KILL)", errmsg(), " (after error: ", args..., ")");
            __builtin_unreachable();
        }
        if (tracee.state == Tracee::UNWAITED and waitid_tracee()) {
            die_impl("waitid(tracee)", errmsg(), " (after error: ", args..., ")");
            __builtin_unreachable();
        }
        die_impl(args...);
        __builtin_unreachable();
    }

    template <class... Args>
    void die_if_err(bool failed, const Args&... args) noexcept {
        static_assert(
            sizeof...(Args) > 0, "Description of the cause of the error is necessary");
        if (failed) {
            die(args..., errmsg());
        }
    }

    void run_tracee(const sandbox::Options& options) noexcept {
        const auto supervisor_euid = geteuid();
        const auto supervisor_egid = getegid();
        if (supervisor_euid == 0) {
            die("Sandbox is not secure if run as root/sudo");
        }

        int child_pidfd{};
        clone_args cl_args = {
            .flags = CLONE_PIDFD | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID,
            .pidfd = reinterpret_cast<uintptr_t>(&child_pidfd),
            .exit_signal = SIGCHLD,
        };
        tracee.pid = syscalls::clone3(&cl_args);
        die_if_err(tracee.pid == -1, "clone3()");
        if (tracee.pid == 0) {
            // Child process
            sandbox::tracee::execute(
                options, std::move(error_fd), supervisor_euid, supervisor_egid);
            __builtin_unreachable();
        }
        // Parent process
        tracee.pidfd = child_pidfd;
        assert(tracee.state == Tracee::NOT_STARTED);
        tracee.state = Tracee::KILLABLE;
    }

    void die_on_tracee_error() noexcept {
        assert(tracee.state == Tracee::WAITED);
        auto pos = lseek(error_fd, 0, SEEK_CUR);
        die_if_err(pos == -1, "lseek()");
        if (pos > 0) {
            _exit(1); // Tracee has already set an error
        }
        assert(pos == 0);
    }

    void wait_tracee() noexcept { die_if_err(waitid_tracee(), "waitid(tracee)"); }

    [[noreturn]] void send_result_to_parent() noexcept {
        // Tracee is dead and waited
        assert(tracee.state == Tracee::WAITED);
        die_on_tracee_error();
        // Tracee was executed and no error was encountered along the way
        sandbox::Result res = {
            .si =
                {
                    .code = tracee.si.si_code,
                    .status = tracee.si.si_status,
                },
            .runtime = 0ns, // TODO: TODO
            .cpu_runtime = total_cpu_time,
            .vm_peak = total_vm_peak,
        };
        (void)write_all(
            error_fd, &res,
            sizeof(res)); // if it fails, we detect it in the parent
        _exit(0);
    }
};

} // namespace

namespace sandbox::supervisor {

void execute(const Options& options, FileDescriptor error_fd) noexcept {
    Supervisor sup{std::move(error_fd)};
    sup.run_tracee(options);
    // TODO: ptrace
    // TODO: timers
    // TODO: do do_in_parent_after_fork() equivalent
    sup.wait_tracee();
    sup.send_result_to_parent();
    // TODO: handle handle SIGINT, SIGTERM and SIGQUIT gracefully --> kill child and send
    // message such as "supervisor received SIGTERM"
}

} // namespace sandbox::supervisor
