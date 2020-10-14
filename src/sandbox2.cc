#include "simlib/sandbox2.hh"
#include "sandbox2_supervisor.hh"
#include "simlib/concat_tostr.hh"
#include "simlib/debug.hh"
#include "simlib/file_contents.hh"
#include "simlib/file_descriptor.hh"
#include "simlib/syscalls.hh"

#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <type_traits>
#include <unistd.h>

namespace sandbox {

[[nodiscard]] std::string Result::si_description() const {
    auto signal_description = [](const char* prefix, int signum) {
        auto abbrv = sigabbrev_np(signum);
        auto descr = sigdescr_np(signum);
        if (abbrv) {
            if (descr) {
                return concat_tostr(prefix, ' ', abbrv, " - ", descr);
            }
            return concat_tostr(prefix, ' ', abbrv);
        }
        if (descr) {
            return concat_tostr(prefix, " with number ", signum, " - ", descr);
        }
        return concat_tostr(prefix, " with number ", signum);
    };
    switch (si.code) {
    case CLD_EXITED: return concat_tostr("exited with ", si.status);
    case CLD_KILLED: return signal_description("killed by signal", si.status);
    case CLD_DUMPED: return signal_description("killed and dumped by signal", si.status);
    case CLD_TRAPPED: return signal_description("trapped by signal", si.status);
    case CLD_STOPPED: return signal_description("stopped by signal", si.status);
    case CLD_CONTINUED: return signal_description("continued by signal", si.status);
    }
    return "unable to describe";
}

future execute(const Options& options) {
    FileDescriptor supervisor_pidfd;
    FileDescriptor error_fd{memfd_create("sandbox errors", MFD_CLOEXEC)};
    if (not error_fd.is_open()) {
        THROW("memfd_create()", errmsg());
    }

    int child_pidfd{};
    clone_args cl_args = {
        .flags = CLONE_PIDFD,
        .pidfd = reinterpret_cast<uintptr_t>(&child_pidfd),
        .exit_signal = SIGCHLD,
    };
    auto pid = syscalls::clone3(&cl_args);
    if (pid == -1) {
        THROW("clone3()", errmsg());
    }
    if (pid == 0) {
        supervisor::execute(options, std::move(error_fd));
        __builtin_unreachable();
    }
    // Parent process
    supervisor_pidfd = child_pidfd;
    return {std::move(supervisor_pidfd), std::move(error_fd)};
}

Result future::get() {
    if (not supervisor_pidfd.is_open()) {
        THROW("future already retrieved");
    }
    siginfo_t si;
    if (syscalls::waitid(P_PIDFD, supervisor_pidfd, &si, WEXITED, nullptr)) {
        THROW("waitid()", errmsg());
    }
    (void)supervisor_pidfd.close();
    // Receive result or error
    if (si.si_code != CLD_EXITED or si.si_status != 0) {
        // Error
        off_t pos = lseek(error_fd, 0, SEEK_CUR);
        if (pos == -1) {
            THROW("lseek()", errmsg());
        }
        if (pos == 0) {
            THROW(
                "supervisor died without an error message (si_code: ", si.si_code,
                ", si_status: ", si.si_status, ')');
        }
        std::string msg(pos, '\0');
        if (pread_all(error_fd, 0, msg.data(), msg.size()) != msg.size()) {
            THROW("read()", errmsg());
        }
        THROW(msg);
    }
    // Result
    static_assert(
        std::is_trivially_copyable_v<Result>,
        "needed to memcpy() it through a file descriptor");
    Result res{};
    if (pread_all(error_fd, 0, &res, sizeof(res)) != sizeof(res)) {
        if (errno == 0) {
            THROW("supervisor did not pass the whole result");
        }
        THROW("read()", errmsg());
    }
    (void)error_fd.close(); // Not needed anymore
    return res;
}

future::~future() {
    if (supervisor_pidfd.is_open()) {
        std::terminate();
    }
}

} // namespace sandbox
