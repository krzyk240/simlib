#pragma once

#include "simlib/file_descriptor.hh"
#include "simlib/string_view.hh"

#include <chrono>
#include <cstdint>
#include <optional>
#include <sched.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace sandbox {

struct Options {
    struct NewIOFileDescriptors {
        int stdin = STDIN_FILENO; // if negative, use /dev/null
        int stdout = STDOUT_FILENO; // if negative, use /dev/null
        int stderr = STDERR_FILENO; // if negative, use /dev/null
    } new_io_fds;

    struct Limits {
        // TODO: check that limits (if set) are non-negative and that limits set to 0 works
        // Real time limit for the root process
        std::optional<std::chrono::nanoseconds> real_time;
        // CPU time limit; if not set, and real time limit is set, then CPU time limit will be
        // set to round(real time limit in seconds) + 1
        std::optional<std::chrono::nanoseconds> cpu_time;
        // Memory limit in bytes, will be rounded down to system page size; limits total
        // virtual memory size
        std::optional<uint64_t> memory_limit;
        std::optional<uint64_t> stack_size_limit; // in bytes
        // Whether to allow executing other programs using execve() and execveat()
        bool allow_execve = false;
        // Maximum number of concurrent processes / threads that may be created; when > 1, then
        // cpu_time cannot be limited as this is not currently possible
        unsigned max_proc_num = 1;
        // Mask of CPUs to allow program to run (see sched_affinity()); a clever use case is to
        // set it to allow only one CPU, so that the program and all its descendants are run on
        // a single core
        std::optional<cpu_set_t> cpu_affinity_mask;
    } limits;

    struct BindMount {
        CStringView source; // path to file or directory to bind mount
        CStringView dest; // path at which to bind mount
        bool read_only = true; // make the mount read-only
        bool no_exec = true; // do not allow executing programs from this mount
        bool recursive = true; // create a recursive bind mount
    };

    struct FsOptions {
        size_t size = 1 << 20; // in bytes, will be rounded up to entire pages
        bool read_only = true; // make the mount read-only
        bool no_exec = true; // do not allow executing programs from this mount
        std::vector<BindMount> mounts;
    } fs;

    CStringView executable; // path to program to run
    std::vector<CStringView> args; // executable args (same as for execve())
};

struct Result {
    struct {
        int code; // siginfo_t::si_code from waitid() of the root process
        int status; // siginfo_t::si_status from waitid() of the root process
    } si{};

    // Runtime (real time) of the root process
    std::chrono::nanoseconds runtime{0};
    // Total runtime (CPU time) of all processes
    std::chrono::nanoseconds cpu_runtime{0};
    // Peak total virtual memory size of all processes (in bytes)
    uint64_t vm_peak = 0;

    // Returns textual description of si field
    [[nodiscard]] std::string si_description() const;
    // TODO: check that si_description is filled successfully on exit(0)
};

class future {
    FileDescriptor supervisor_pidfd;
    FileDescriptor error_fd;

    future(FileDescriptor supervisor_pidfd, FileDescriptor error_fd) noexcept
    : supervisor_pidfd{std::move(supervisor_pidfd)}
    , error_fd{std::move(error_fd)} {}

public:
    future(const future&) = delete;
    future(future&&) noexcept = default;
    future& operator=(const future&) = delete;
    future& operator=(future&&) noexcept = default;

    ~future(); // Not retrieved future will call std::terminate()

    // Retrieves result, throws an instance of std::runtime_error on error
    Result get();

    friend future execute(const Options& options);
};

// Throws on error
future execute(const Options& options);

} // namespace sandbox
