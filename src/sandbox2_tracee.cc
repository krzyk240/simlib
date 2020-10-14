#include "sandbox2_tracee.hh"
#include "simlib/debug.hh"
#include "simlib/file_contents.hh"
#include "simlib/file_descriptor.hh"
#include "simlib/file_manip.hh"
#include "simlib/path.hh"
#include "simlib/sandbox2.hh"
#include "simlib/string_traits.hh"
#include "simlib/syscalls.hh"
#include "simlib/working_directory.hh"

#include <csignal>
#include <cstdint>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <linux/wait.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>

namespace {

struct Tracee {
    const sandbox::Options& options;
    const uid_t supervisor_euid;
    const uid_t supervisor_egid;
    FileDescriptor error_fd;

    FileDescriptor execfd{};
    std::optional<std::vector<const char*>> argv_holder; // trick to allow noexcept constructor

    template <class... Args>
    // NOLINTNEXTLINE(readability-make-member-function-const)
    [[noreturn]] void die(const Args&... args) noexcept {
        static_assert(sizeof...(Args) > 0, "error message cannot be empty");
        for (auto msg : {StringView{args}...}) {
            if (not msg.empty()) {
                (void)write_all(error_fd, msg);
            }
        }
        _exit(42);
    }

    template <class... Args>
    void die_if_err(bool failed, const Args&... args) noexcept {
        static_assert(
            sizeof...(Args) > 0, "Description of the cause of an error is necessary");
        if (failed) {
            die(args..., errmsg());
        }
    }

    void write_proc_file(CStringView file_path, StringView contents) noexcept {
        FileDescriptor fd{open(file_path.data(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)};
        die_if_err(not fd.is_open(), "open(", file_path, ")");
        die_if_err(write_all(fd, contents) != contents.size(), "write(", file_path, ")");
    }

    template <class T>
    void write_id_mapping(CStringView file_path, T id) noexcept {
        auto id_str = to_string(id);
        constexpr StringView pref = "1000 ";
        constexpr StringView suff = " 1";
        InplaceBuff<pref.size() + decltype(id_str)::max_size() + suff.size()> str{
            std::in_place, pref, id_str, suff};
        write_proc_file(file_path, str);
    }

    void setup_user_namespace() noexcept {
        write_id_mapping("/proc/self/uid_map", supervisor_euid);
        write_proc_file("/proc/self/setgroups", "deny");
        write_id_mapping("/proc/self/gid_map", supervisor_egid);
    }

    void prepare_executable() noexcept {
        execfd = open(options.executable.data(), O_PATH | O_CLOEXEC);
        die_if_err(not execfd.is_open(), "open(", options.executable, ")");
    }

    void perform_bind_mounts() noexcept {
        try {
            for (auto const& mnt : options.fs.mounts) {
                auto abs_dest = path_absolute(mnt.dest, "/");
                auto dest = concat("/proc/", StringView(abs_dest).without_leading('/'));
                die_if_err(mkdir(dest) and errno != EEXIST, "mkdir(\"", dest, "\")");
                int flags = MS_BIND | (mnt.recursive ? MS_REC : 0);
                die_if_err(
                    mount(mnt.source.data(), dest.to_cstr().data(), nullptr, flags, nullptr),
                    "mount(bind: \"", mnt.source, "\" -> \"", dest.to_cstr(), "\")");
                // Remount to set specified flags
                flags |= MS_REMOUNT | MS_NOSUID;
                if (mnt.read_only) {
                    flags |= MS_RDONLY;
                }
                if (mnt.no_exec) {
                    flags |= MS_NOEXEC;
                }
                die_if_err(
                    mount(nullptr, dest.to_cstr().data(), nullptr, flags, nullptr),
                    "mount(bind remount: \"", dest, "\")");
            }
        } catch (...) {
            die("performing bind mounts", errmsg(ENOMEM));
        }
    }

    void setup_fs() noexcept {
        die_if_err(mount(nullptr, "/", nullptr, MS_PRIVATE, nullptr), "mount(mk_private:/)");
        // /proc/ is insecure to use (as a bind mount) and we will use it as a new root
        try {
            // TODO: what if source is a symlink???
            auto cwd = get_cwd().to_string();
            for (auto const& mnt : options.fs.mounts) {
                auto path = path_absolute(mnt.source, cwd);
                if (has_prefix(path, "/proc/") or path == "/proc") {
                    die("mount source: \"", mnt.source,
                        R"(" uses "/proc/" that is forbidden to be used)");
                }
            }

        } catch (...) {
            die("checking bind mounts' sources", errmsg(ENOMEM));
        }

        // Set up a new root filesystem
        int root_mount_flags = MS_NOSUID | MS_SILENT | (options.fs.no_exec ? MS_NOEXEC : 0);
        // MS_RDONLY will be set later, because we need the filesystem to be writable during
        // bind mounts
        auto root_mount_data = [&]() noexcept {
            constexpr StringView prefix = "size=";
            auto fs_size_str = to_string(options.fs.size);
            return InplaceBuff<prefix.size() + decltype(fs_size_str)::max_size() + 1>{
                std::in_place, prefix, fs_size_str}; // +1 for trailing null
        }();
        die_if_err(
            mount(
                "tmpfs", "/proc", "tmpfs", root_mount_flags, root_mount_data.to_cstr().data()),
            "mount(tmpfs at \"/proc\")");
        perform_bind_mounts();
        // Make the new root filesystem read only
        if (options.fs.read_only) {
            die_if_err(
                mount(
                    nullptr, "/proc", nullptr, root_mount_flags | MS_REMOUNT | MS_RDONLY,
                    root_mount_data.to_cstr().data()),
                "mount(remounting tmpfs at \"/proc\")");
        }

        // Make all mounts private
        die_if_err(
            mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr),
            "mount(recursive mk_private on \"/\")");

        // Switch to the new root filesystem
        die_if_err(chdir("/proc/"), R"(chdir("/proc/"))");
        die_if_err(syscalls::pivot_root(".", "."), R"(pivot_root(".", ".")");
        die_if_err(umount2(".", MNT_DETACH), R"(umount2("."))");
    }

    void drop_capabilities() noexcept {
        // Set and lock securebits while we have capabilities
        die_if_err(
            cap_set_secbits(
                SECBIT_NOROOT_LOCKED | SECBIT_NOROOT | SECBIT_NO_CAP_AMBIENT_RAISE |
                SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED),
            "cap_set_secbits()");
        // Drop all capabilities
        cap_t caps = cap_init();
        die_if_err(caps == nullptr, "cap_init()");
        die_if_err(cap_clear(caps), "cap_clear()");
        die_if_err(cap_set_proc(caps), "cap_set_proc()");
        die_if_err(cap_free(caps), "cap_free()");
        die_if_err(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(PR_SET_NO_NEW_PRIVS)");
    }

    void reset_signals() noexcept {
        // Reset blocked signals
        sigset_t sigset;
        die_if_err(sigemptyset(&sigset), "sigemptyset()");
        die_if_err(sigprocmask(SIG_SETMASK, &sigset, nullptr), "sigprocmask()");
        // Reset SIGPIPE (may be used to kill the process e.g. in an interactive task)
        struct sigaction sa {};
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_DFL;
        die_if_err(sigaction(SIGPIPE, &sa, nullptr), "sigaction(SIGPIPE)");
    }

    void prepare_argv() noexcept {
        try {
            argv_holder.emplace(options.args.size() + 1);
            for (size_t i = 0; i < options.args.size(); ++i) {
                (*argv_holder)[i] = options.args[i].data();
            }
            argv_holder->back() = nullptr;
        } catch (...) {
            die("preparing argv for execveat()", errmsg(ENOMEM));
        }
    }

    void set_limits() noexcept {
        // TODO: TODO
    }

    void install_seccomp() noexcept {
        // TODO: TODO
    }

    [[noreturn]] void execute() noexcept {
        die_if_err(
            syscalls::execveat(
                execfd, "", const_cast<char* const*>(argv_holder->data()), environ,
                AT_EMPTY_PATH),
            "execveat()");
        __builtin_unreachable();
    }
};

} // namespace

namespace sandbox::tracee {

void execute(
    const Options& options, FileDescriptor error_fd, uid_t supervisor_euid,
    gid_t supervisor_egid) noexcept {
    Tracee tra = {
        .options = options,
        .supervisor_euid = supervisor_euid,
        .supervisor_egid = supervisor_egid,
        .error_fd = std::move(error_fd),
    };
    tra.setup_user_namespace();
    tra.prepare_executable();
    tra.setup_fs();
    tra.drop_capabilities();
    tra.reset_signals();
    tra.prepare_argv();
    tra.set_limits();
    tra.install_seccomp();
    tra.execute();
}

} // namespace sandbox::tracee
