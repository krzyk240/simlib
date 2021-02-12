#include "sandbox2_supervisor.hh"
#include "sandbox2_tracee.hh"
#include "simlib/debug.hh"
#include "simlib/file_contents.hh"
#include "simlib/file_descriptor.hh"
#include "simlib/pipe.hh"
#include "simlib/proc_status_file.hh"
#include "simlib/sandbox2.hh"
#include "simlib/string_transform.hh"
#include "simlib/string_view.hh"
#include "simlib/syscalls.hh"
#include "simlib/to_string.hh"
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
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

using std::chrono_literals::operator""ns;
using std::optional;

namespace {

constexpr DebugLogger<true, true> debuglog{};

struct Supervisor {
    FileDescriptor error_fd;

    // The process with pid 1 (init process) in the new user namespace
    struct TraceeInit {
        // State automaton:
        //                          process died, but supervisor did not kill it
        //                           ,--------------------------------------.
        //                          /         waitid_tracee_init()          |
        // --> NOT_STARTED         /                                        v
        //          `--------> KILLABLE ----------> UNWAITED -----------> WAITED
        //     run_tracee_init()     kill_tracee_init()   waitid_tracee_init()
        enum State {
            NOT_STARTED,
            KILLABLE, // started but neither killed nor waited
            UNWAITED, // killed but not waited
            WAITED, // dead and waited
        } state = NOT_STARTED;
        pid_t pid = 0;
        FileDescriptor pidfd;
        siginfo_t si{};
        FileDescriptor ptrace_sync_fd;
    } tracee_init;

    // The process that executes sandbox::Options::executable
    struct MainTracee {
        // State automaton:
        //                                            handling main_tracee death
        //                                                 ,---------.
        // --> NOT_STARTED ----------------------> UNWAITED           `-> WAITED
        //                 first PTRACE_EVENT_EXEC
        enum State {
            NOT_STARTED,
            UNWAITED, // started but not waited
            WAITED, // dead and waited
        } state = NOT_STARTED;
        pid_t pid = 0;
        siginfo_t si{};
        // TODO: sth to account for real time
    } main_tracee;

    // Process hierarchy looks as follows:
    // caller of sandbox::execute()
    // `--> supervisor process
    //      `---> tracee_init
    //            `---> main_tracee

    std::chrono::nanoseconds total_cpu_time{0};
    uint64_t total_vm_peak = 0; // in bytes

    struct TraceeInfo {
        pid_t tgid; // thread group id
        FileDescriptor proc_status{}; // if open, holds fd of /proc/$tid/status
    };
    // Trick to allow noexcept constructor
    optional<std::map<pid_t, TraceeInfo>> tracees_holder{}; // thread id -> TraceeInfo

    explicit Supervisor(FileDescriptor error_fd) noexcept
    : error_fd{std::move(error_fd)} {}

    Supervisor(const Supervisor&) = delete;
    Supervisor(Supervisor&&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;
    Supervisor& operator=(Supervisor&&) = delete;
    ~Supervisor() = default;

    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[nodiscard]] auto kill_tracee_init() noexcept {
        assert(tracee_init.state == TraceeInit::KILLABLE);
        debuglog.verbose("kill(tracee_init)");
        auto res = syscalls::pidfd_send_signal(tracee_init.pidfd, SIGKILL, nullptr, 0);
        tracee_init.state = TraceeInit::UNWAITED;
        return res;
    }

    [[nodiscard]] auto waitid_tracee_init() noexcept {
        assert(is_one_of(tracee_init.state, TraceeInit::KILLABLE, TraceeInit::UNWAITED));
        auto res =
            syscalls::waitid(P_PIDFD, tracee_init.pidfd, &tracee_init.si, WEXITED, nullptr);
        debuglog.verbose(
            "waitid(tracee_init, {pid: ", tracee_init.si.si_pid,
            ", signo: ", tracee_init.si.si_signo, ", code: ", tracee_init.si.si_code,
            ", status: ", tracee_init.si.si_status, "})");
        tracee_init.state = TraceeInit::WAITED;
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
        if (tracee_init.state == TraceeInit::KILLABLE and kill_tracee_init() and
            errno != ESRCH) {
            // ESRCH may appear if the process has already died
            die_impl(
                "pidfd_send_signal(tracee_init, KILL)", errmsg(), " (after error: ", args...,
                ")");
            __builtin_unreachable();
        }
        if (tracee_init.state == TraceeInit::UNWAITED and waitid_tracee_init()) {
            die_impl("waitid(tracee_init)", errmsg(), " (after error: ", args..., ")");
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

    void initialize(pid_t parent_pid) noexcept {
        // New process name
        die_if_err(prctl(PR_SET_NAME, "supervisor", 0, 0, 0), "prctl(PR_SET_NAME)");
        // Kill us if our parent dies
        die_if_err(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0), "prctl(PR_SET_PDEATHSIG)");
        // Ensure our parent did not die before we set PR_SET_PDEATHSIG
        if (getppid() != parent_pid) {
            die("creator of supervisor process died");
        }
    }

    template <class Func>
    decltype(auto) die_on_exception(Func&& func, StringView description) noexcept {
        try {
            return std::forward<Func>(func)();
        } catch (const std::exception& e) {
            die(description, ": ", e.what());
        } catch (...) {
            die(description, ": unknown exception");
        }
    }

    void sync_with_tracee_init(Pipe sync_pipe) {
        char val{};
        die_if_err(sync_pipe.writable.close(), "close(sync_pipe.writable)");
        auto rc = read(sync_pipe.readable, &val, 1);
        if (rc == 0) {
            die("read(sync_pipe) == 0");
        }
        die_if_err(rc == -1, "read(sync_pipe)");
        assert(rc == 1);
        die_if_err(sync_pipe.readable.close(), "close(sync_pipe.readable)");
    }

    void run_tracee_init(const sandbox::Options& options) noexcept {
        const auto supervisor_euid = geteuid();
        const auto supervisor_egid = getegid();
        if (supervisor_euid == 0) {
            die("Sandbox is not secure if run as root/sudo");
        }

        tracee_init.ptrace_sync_fd = eventfd(0, EFD_CLOEXEC);
        die_if_err(not tracee_init.ptrace_sync_fd.is_open(), "eventfd()");

        auto sync_pipe = [&] {
            auto pipe_opt = pipe2(O_CLOEXEC);
            die_if_err(not pipe_opt, "pipe2()");
            return std::move(*pipe_opt);
        }();

        int child_pidfd{};
        clone_args cl_args = {
            .flags = CLONE_PIDFD | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID,
            .pidfd = reinterpret_cast<uintptr_t>(&child_pidfd),
            .exit_signal = SIGCHLD,
        };
        tracee_init.pid = syscalls::clone3(&cl_args);
        die_if_err(tracee_init.pid == -1, "clone3()");
        if (tracee_init.pid == 0) {
            // Child process
            sandbox::tracee::execute(
                options, std::move(error_fd), std::move(sync_pipe),
                std::move(tracee_init.ptrace_sync_fd), supervisor_euid, supervisor_egid);
            __builtin_unreachable();
        }
        // Parent process
        tracee_init.pidfd = child_pidfd;
        assert(tracee_init.state == TraceeInit::NOT_STARTED);
        tracee_init.state = TraceeInit::KILLABLE;

        sync_with_tracee_init(std::move(sync_pipe));
    }

    void die_on_tracee_error() noexcept {
        assert(tracee_init.state == TraceeInit::WAITED);
        assert(is_one_of(main_tracee.state, MainTracee::NOT_STARTED, MainTracee::WAITED));
        auto pos = lseek(error_fd, 0, SEEK_CUR);
        die_if_err(pos == -1, "lseek()");
        if (pos > 0) {
            _exit(1); // Tracee has already set an error
        }
        assert(pos == 0);
    }

    void start_ptrace() noexcept {
        if (ptrace(
                PTRACE_SEIZE, tracee_init.pid, nullptr,
                PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                    PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                    PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACESECCOMP))
        {
            int ptrace_errnum = errno;
            die_if_err(
                kill_tracee_init() and errno != ESRCH, "pidfd_send_signal(tracee_init, KILL)");
            die_if_err(waitid_tracee_init(), "waitid(tracee_init)");
            die_on_tracee_error(); // error in tracee_init may have caused the ptrace() error
                                   // e.g. by making the tracee_init exit before ptrace() call
            die("ptrace(SEIZE)", errmsg(ptrace_errnum));
        }
        // Signal tracee_init that it became traced
        eventfd_t x = 1;
        die_if_err(eventfd_write(tracee_init.ptrace_sync_fd, x), "eventfd_write(ptrace_sync)");
        die_if_err(
            tracee_init.ptrace_sync_fd.close(), "close()"); // fd is not needed from now on
    }

    void construct_tracees_holder() noexcept {
        die_on_exception([&] { tracees_holder.emplace(); }, "map::map()");
    }

    void remove_tracee(pid_t tid) noexcept {
        debuglog("    remove tracee [", tid, "]");
        die_on_exception([&] { tracees_holder->erase(tid); }, "map::erase()");
    }

    FileDescriptor get_proc_status_fd(pid_t tid) noexcept {
        FileDescriptor fd = open_proc_status(tid);
        die_if_err(not fd.is_open(), "open(\"/proc/", to_string(tid), "/status\")");
        return fd;
    }

    pid_t get_tgid(int proc_status_fd, pid_t tid) noexcept {
        return die_on_exception(
            [&] {
                auto str = field_from_proc_status(proc_status_fd, "Tgid");
                auto tgid_opt = str2num<pid_t>(str);
                die_if_err(
                    not tgid_opt, "/proc/", to_string(tid),
                    "/status field Tgid has value that is not a number: ", str);
                return *tgid_opt;
            },
            "field_from_proc_status()");
    }

    // Creates tracee info unless it existed and returns reference to it
    TraceeInfo& tracee_info(pid_t tid) noexcept {
        return die_on_exception(
            [&]() -> TraceeInfo& {
                auto [it, created] = tracees_holder->try_emplace(tid);
                if (not created) {
                    return it->second;
                }
                // Just created
                FileDescriptor proc_status = get_proc_status_fd(tid);
                pid_t tgid = get_tgid(proc_status, tid);
                it->second = {
                    .tgid = tgid,
                    .proc_status = std::move(proc_status),
                };
                debuglog("    add tracee [", tid, "], TGID: ", tgid);
                // TODO: update VM information
                return it->second;
            },
            "map::try_emplace()");
    }

    static const char* sig_name(int sig) noexcept {
        auto res = sigabbrev_np(sig);
        return res ? res : "unknown";
    }

    static const char* sig_descr(int sig) noexcept {
        auto res = sigdescr_np(sig);
        return res ? res : "unknown";
    }

    // Returns received event message or std::nullopt if tracee died
    template <class T>
    optional<T> ptrace_geteventmsg(pid_t tid) noexcept {
        unsigned long val{}; // NOLINT(google-runtime-int)
        if (ptrace(PTRACE_GETEVENTMSG, tid, 0, &val)) {
            if (errno == ESRCH) {
                return std::nullopt;
            }
            die_if_err(true, "ptrace(GETEVENTMSG)");
        }
        return static_cast<T>(val);
    }

    struct [[nodiscard]] RestartTracee {
        decltype(PTRACE_CONT) ptrace_op; // PTRACE_CONT, PTRACE_LISTEN, or PTRACE_SYSCALL
        int sig; // 0 means no signal
    };

    static RestartTracee process_ptrace_event_clone(siginfo_t& si) {
        debuglog("[", si.si_pid, "] CLONE");
        return {PTRACE_CONT, 0};
    }

    static RestartTracee process_ptrace_event_fork(siginfo_t& si) {
        debuglog("[", si.si_pid, "] FORK");
        return {PTRACE_CONT, 0};
    }

    static RestartTracee process_ptrace_event_vfork(siginfo_t& si) {
        debuglog("[", si.si_pid, "] VFORK");
        return {PTRACE_CONT, 0};
    }

    static RestartTracee process_ptrace_event_vfork_done(siginfo_t& si) noexcept {
        debuglog("[", si.si_pid, "] VFORK_DONE");
        return {PTRACE_CONT, 0};
    }

    optional<RestartTracee> process_ptrace_event_exec(siginfo_t& si) noexcept {
        // First EXEC happens in the main_tracee
        if (main_tracee.state == MainTracee::NOT_STARTED) {
            debuglog("[", si.si_pid, "] EXEC (main_tracee)");
            main_tracee.state = MainTracee::UNWAITED;
            main_tracee.pid = si.si_pid;
        } else {
            debuglog("[", si.si_pid, "] EXEC");
        }
        // Kernel guarantees that this event happens after every thread that neither the caller
        // of this exec() nor the thread group leader is dead and waited by this moment
        auto former_tid_opt = ptrace_geteventmsg<pid_t>(si.si_pid);
        if (not former_tid_opt) {
            return std::nullopt;
        }
        pid_t former_tid = *former_tid_opt;
        if (former_tid == si.si_pid) { // TID did not change and TID == TGID
            // TODO: update VM information
            return RestartTracee{PTRACE_CONT, 0};
        }
        remove_tracee(former_tid);
        // Reuse entry of the thread group leader, as si.si_pid == TID == TGID of this thread
        assert(tracees_holder->count(si.si_pid) == 1);
        // TODO: update VM information
        return RestartTracee{PTRACE_CONT, 0};
    }

    RestartTracee process_ptrace_event_exit(siginfo_t& si) noexcept {
        debuglog("[", si.si_pid, "] EXIT");
        (void)tracee_info(
            si.si_pid); // may create a record for the new tracee e.g. when new process gets
                        // SIGKILLed before we receive PTRACE_EVENT_STOP and kernel generates
                        // PTRACE_EVENT_EXIT before killing the tracee
        // TODO: update VM information
        return {PTRACE_CONT, 0};
    }

    static RestartTracee process_ptrace_event_seccomp(siginfo_t& si) noexcept {
        debuglog("[", si.si_pid, "] SECCOMP");
        std::abort(); // TODO: TODO
        // TODO: update VM information (if necessary)
        return {PTRACE_CONT, 0};
    }

    RestartTracee process_ptrace_event_stop_new_tracee(siginfo_t& si) noexcept {
        debuglog("[", si.si_pid, "] STOP in new tracee");
        // This event may happen before CLONE, FORK, VFORK event due to the fact that the two
        // processes run concurrently. Moreover, it may not happen at all e.g. when the new
        // tracee is SIGKILLed, then only tracee death may be observed (and maybe EXIT event,
        // depending on the kernel implementation)
        (void)tracee_info(si.si_pid); // may create a record for the new tracee
        return {PTRACE_CONT, 0};
    }

    RestartTracee process_ptrace_event_stop(siginfo_t& si) noexcept {
        auto sig = si.si_status ^ (PTRACE_EVENT_STOP << 8);
        switch (sig) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU: return process_ptrace_event_stop_group_stop(si, sig);
        default:
            // new-tracee-attached-stop or PTRACE_INTERRUPT-stop, both have sig == SIGTRAP;
            // PTRACE_INTERRUPT-stop should not happen as we don't use PTRACE_INTERRUPT
            assert(sig == SIGTRAP);
            return process_ptrace_event_stop_new_tracee(si);
        }
    }

    static RestartTracee process_ptrace_syscall_stop(siginfo_t& si) noexcept {
        debuglog("[", si.si_pid, "] syscall stop");
        std::abort(); // TODO: TODO
        return {PTRACE_CONT, 0};
    }

    static RestartTracee process_ptrace_signal_delivery_stop(siginfo_t& si) noexcept {
        auto sig = si.si_status;
        debuglog("[", si.si_pid, "] signal-delivery-stop: ", sig_name(sig));
        return {PTRACE_CONT, sig};
    }

    optional<RestartTracee> process_ptrace_event(siginfo_t& si) noexcept {
        assert(si.si_code == CLD_TRAPPED);
        switch (si.si_status >> 8) {
        case PTRACE_EVENT_CLONE:
            assert((si.si_status ^ (PTRACE_EVENT_CLONE << 8)) == SIGTRAP);
            return process_ptrace_event_clone(si);
        case PTRACE_EVENT_FORK:
            assert((si.si_status ^ (PTRACE_EVENT_FORK << 8)) == SIGTRAP);
            return process_ptrace_event_fork(si);
        case PTRACE_EVENT_VFORK:
            assert((si.si_status ^ (PTRACE_EVENT_VFORK << 8)) == SIGTRAP);
            return process_ptrace_event_vfork(si);
        case PTRACE_EVENT_VFORK_DONE:
            assert((si.si_status ^ (PTRACE_EVENT_VFORK_DONE << 8)) == SIGTRAP);
            return process_ptrace_event_vfork_done(si);
        case PTRACE_EVENT_EXEC:
            assert((si.si_status ^ (PTRACE_EVENT_EXEC << 8)) == SIGTRAP);
            return process_ptrace_event_exec(si);
        case PTRACE_EVENT_EXIT:
            assert((si.si_status ^ (PTRACE_EVENT_EXIT << 8)) == SIGTRAP);
            return process_ptrace_event_exit(si);
        case PTRACE_EVENT_SECCOMP: {
            assert((si.si_status ^ (PTRACE_EVENT_SECCOMP << 8)) == SIGTRAP);
            return process_ptrace_event_seccomp(si);
        case PTRACE_EVENT_STOP:
            // si.si_status contains the stopping signal if it is a group-stop
            return process_ptrace_event_stop(si);
        case 0:
            if (si.si_status == (SIGTRAP | 0x80)) {
                return process_ptrace_syscall_stop(si);
            }
            return process_ptrace_signal_delivery_stop(si);
        }
        }
        die("unknown siginfo_t::si_status for si_code == CLD_TRAPPED: ",
            to_string(si.si_status));
    }

    void process_event(siginfo_t& si) noexcept {
        auto debuglog_intercepted_signal = [&](StringView description) {
            debuglog(
                "[", si.si_pid, "] ", description, " by signal ", sig_name(si.si_status),
                ", nothing to do");
        };

        switch (si.si_code) {
        case CLD_EXITED:
        case CLD_KILLED:
        case CLD_DUMPED:
            debuglog("[", si.si_pid, "] terminated");
            if (si.si_pid == tracee_init.pid) {
                die_if_err(waitid_tracee_init(), "waitid(tracee_init)");
                remove_tracee(tracee_init.pid);
                return;
            }
            // Non-init tracee
            die_if_err(
                syscalls::waitid(P_PID, si.si_pid, &si, __WALL | WEXITED, nullptr),
                "waitid()");
            if (si.si_pid == main_tracee.pid) {
                assert(main_tracee.state == MainTracee::UNWAITED);
                main_tracee.state = MainTracee::WAITED;
                main_tracee.si = si;
                // TODO: set real time runtime of main_tracee here or after everyone is dead?
            }
            remove_tracee(si.si_pid);
            // TODO: update VM information
            return;
        case CLD_STOPPED: debuglog_intercepted_signal("stopped"); return;
        case CLD_CONTINUED: debuglog_intercepted_signal("continued"); return;
        case CLD_TRAPPED:
            auto restart_cmd = process_ptrace_event(si);
            if (not restart_cmd) {
                return; // Nothing to do
            }
            assert(
                is_one_of(restart_cmd->ptrace_op, PTRACE_CONT, PTRACE_LISTEN, PTRACE_SYSCALL));
            auto cmd_str = [&] {
                switch (restart_cmd->ptrace_op) {
                case PTRACE_CONT: return "CONT";
                case PTRACE_LISTEN: return "LISTEN";
                case PTRACE_SYSCALL: return "SYSCALL";
                default: return "?";
                }
            };

            auto rc = ptrace(restart_cmd->ptrace_op, si.si_pid, 0, restart_cmd->sig);
            // Skip ESRCH because tracee could have died in ptrace-stop
            die_if_err(rc != 0 and errno != ESRCH, "ptrace(", cmd_str(), ")");
            return;
        }
        die("unknown siginfo_t::si_code: ", to_string(si.si_code));
    }

    void run_event_loop() noexcept {
        construct_tracees_holder();
        debuglog("add tracee_init [", tracee_init.pid, "]");
        die_on_exception(
            [&] {
                auto [_, inserted] = tracees_holder->try_emplace(
                    tracee_init.pid,
                    TraceeInfo{
                        .tgid = tracee_init.pid,
                        .proc_status =
                            FileDescriptor{}, // do not include tracee_init in statistics
                    });
                assert(inserted);
            },
            "map::try_emplace()");
        for (;;) {
            siginfo_t si;
            // Wait for events
            auto rc = syscalls::waitid(P_ALL, 0, &si, __WALL | WEXITED | WNOWAIT, nullptr);
            if (rc == -1 and errno == ECHILD) {
                // This way is safer than looping until tracees_holder->empty() because it may
                // happen that we see process death before we get an event from its
                // just-created child. E.g. int main() { _exit(fork() != 0); } We could
                // sometimes see: [123] CREATED -- parent [123] DIED -- parent [124] CREATED --
                // this is the event from the new child process
                break;
            }
            die_if_err(rc, "waitid()");
            debuglog.verbose(
                "waitid({pid: ", si.si_pid, ", signo: ", si.si_signo, ", code: ", si.si_code,
                ", status: ", si.si_status, "})");
            process_event(si);
        }
        assert(tracees_holder->empty());
    }

    [[noreturn]] void send_result_to_parent() noexcept {
        // Every tracee (including init and main) is dead and waited
        assert(tracee_init.state == TraceeInit::WAITED);
        assert(is_one_of(main_tracee.state, MainTracee::NOT_STARTED, MainTracee::WAITED));
        assert(tracees_holder->empty());
        die_on_tracee_error();
        if (main_tracee.state == MainTracee::NOT_STARTED) {
            // main_tracee did not spawn
            die("tracee_init died without an error message (si_code: ",
                to_string(tracee_init.si.si_code),
                ", si_status: ", to_string(tracee_init.si.si_status), ")");
        }
        // main_tracee was executed and no error was encountered along the way
        sandbox::Result res = {
            .si =
                {
                    .code = main_tracee.si.si_code,
                    .status = main_tracee.si.si_status,
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

void execute(const Options& options, FileDescriptor error_fd, int parent_pid) noexcept {
    // TODO: file descriptors and close() error
    // TODO: remember about forbidding clone() and clone3() with CLONE_UNTRACED and
    // CLONE_NEWUSER
    // TODO: add test for executing non-executable file
    // TODO: add test for multithreading
    // TODO: add test for SIGKILL racing with PTRACE_EVENT_STOP
    Supervisor sup{std::move(error_fd)};
    sup.initialize(parent_pid);
    sup.run_tracee_init(options);
    sup.start_ptrace();
    // TODO: timers
    // TODO: do do_in_parent_after_fork() equivalent
    sup.run_event_loop();
    sup.send_result_to_parent();
    // TODO: handle handle SIGINT, SIGTERM and SIGQUIT gracefully --> kill child and send
    // message such as "supervisor received SIGTERM"
}

} // namespace sandbox::supervisor
