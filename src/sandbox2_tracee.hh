#pragma once

#include "simlib/file_descriptor.hh"
#include "simlib/pipe.hh"
#include "simlib/sandbox2.hh"

namespace sandbox::tracee {

[[noreturn]] void execute(
    const Options& options, FileDescriptor error_fd, Pipe sync_pipe, uid_t supervisor_euid,
    gid_t supervisor_egid) noexcept;

} // namespace sandbox::tracee
