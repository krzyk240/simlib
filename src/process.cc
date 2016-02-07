#include "../include/filesystem.h"
#include "../include/logger.h"
#include "../include/memory.h"
#include "../include/process.h"

#include <dirent.h>
#include <sys/wait.h>

using std::array;
using std::string;
using std::unique_ptr;
using std::vector;

const spawn_opts default_spawn_opts = {
	STDIN_FILENO,
	STDOUT_FILENO,
	STDERR_FILENO
};

int spawn(const char* exec, const char* args[], const struct spawn_opts *opts,
		const char* working_dir) {
	pid_t cpid = fork();
	if (cpid == -1) {
		// TODO: Maybe throw an exception
		errlog(__FILE__, ':', toString(__LINE__), ": ", __PRETTY_FUNCTION__,
			": Failed to fork()", error(errno));
		return -1;

	} else if (cpid == 0) {
		// Change working directory
		if (working_dir != nullptr && working_dir[0] != '\0' &&
			strcmp(working_dir, ".") != 0 && strcmp(working_dir, "./") != 0) {
			if (chdir(working_dir) == -1)
				_exit(-1);
		}

		// Change stdin
		if (opts->new_stdin_fd < 0)
			sclose(STDIN_FILENO);

		else if (opts->new_stdin_fd != STDIN_FILENO)
			while (dup2(opts->new_stdin_fd, STDIN_FILENO) == -1)
				if (errno != EINTR)
					_exit(-1);

		// Change stdout
		if (opts->new_stdout_fd < 0)
			sclose(STDOUT_FILENO);

		else if (opts->new_stdout_fd != STDOUT_FILENO)
			while (dup2(opts->new_stdout_fd, STDOUT_FILENO) == -1)
				if (errno != EINTR)
					_exit(-1);

		// Change stderr
		if (opts->new_stderr_fd < 0)
			sclose(STDERR_FILENO);

		else if (opts->new_stderr_fd != STDERR_FILENO)
			while (dup2(opts->new_stderr_fd, STDERR_FILENO) == -1)
				if (errno != EINTR)
					_exit(-1);

		execvp(exec, (char *const *)args);
		_exit(-1);
	}

	int status;
	waitpid(cpid, &status, 0);
	return status;
}

int spawn(const string& exec, const vector<string>& args,
		const struct spawn_opts *opts, const string& working_dir) {
	// Convert args
	const size_t len = args.size();
	const char *argv[len + 1];
	argv[len] = nullptr;

	for (size_t i = 0; i < len; ++i)
		argv[i] = args[i].c_str();

	return spawn(exec.c_str(), argv, opts, working_dir.c_str());
}

int spawn(const string& exec, size_t argc, string *args,
		const struct spawn_opts *opts, const string& working_dir) {
	// Convert args
	const size_t len = argc;
	const char *argv[len + 1];
	argv[len] = nullptr;

	for (size_t i = 0; i < len; ++i)
		argv[i] = args[i].c_str();

	return spawn(exec.c_str(), argv, opts, working_dir.c_str());
}

std::string getCWD() {
	unique_ptr<char[], delete_using_free<char>> buff(get_current_dir_name());
	if (!buff || buff[0] != '/') {
		if (buff)
			errno = ENOENT; // Improper path, but get_current_dir_name() succeed

		throw std::runtime_error(concat("Failed to get CWD", error(errno)));
	}

	string res(buff.get());
	if (res.back() != '/')
		res += '/';

	return res;
}

string getExec(pid_t pid) {
	array<char, 4096> buff;
	string path = concat("/proc/", toString(pid), "/exe");

	ssize_t rc = readlink(path.c_str(), buff.data(), buff.size());
	if ((rc == -1 && errno == ENAMETOOLONG)
		|| rc >= static_cast<int>(buff.size()))
	{
		array<char, 65536> buff2;
		rc = readlink(path.c_str(), buff2.data(), buff2.size());
		if (rc == -1 || rc >= static_cast<int>(buff2.size()))
			throw std::runtime_error(concat("Failed: readlink()",
				error(errno)));

		return string(buff2.data(), rc);

	} else if (rc == -1)
		throw std::runtime_error(concat("Failed: readlink()", error(errno)));

	return string(buff.data(), rc);
}

vector<pid_t> findProcessesByExec(string exec, bool include_me) {
	if (exec.empty())
		return {};

	if (exec.front() != '/')
		exec = concat(getCWD(), exec);
	// Make exec absolute
	exec = abspath(exec);

	pid_t pid, my_pid = (include_me ? -1 : getpid());
	DIR *dir = opendir("/proc");
	if (dir == nullptr)
		throw std::runtime_error(concat("Cannot open /proc directory",
			error(errno)));

	// Process with deleted exec will have " (deleted)" suffix in result of
	// readlink(2)
	string exec_deleted = concat(exec, " (deleted)");
	ssize_t buff_size = exec_deleted.size() + 1; // +1 - for terminating null

	dirent *file;
	vector<pid_t> res;
	while ((file = readdir(dir)) != nullptr) {
		if (!isDigit(file->d_name))
			continue; // Not a process

		pid = atoi(file->d_name);
		if (pid == my_pid)
			continue; // Do not need to check myself

		// Process exe_path (/proc/pid/exe)
		string exe_path = concat("/proc/", file->d_name, "/exe");

		char buff[buff_size];
		ssize_t len = readlink(exe_path.c_str(), buff, buff_size);
		if (len == -1 || len >= buff_size)
			continue; // Error or name too long

		buff[len] = '\0';

		if (exec == buff || exec_deleted == buff)
			res.push_back(pid); // We have a match
	}

	closedir(dir);
	return res;
}

string chdirToExecDir() {
	string exec = getExec(getpid());
	// Erase file component
	size_t slash = exec.rfind('/');
	if (slash < exec.size())
		exec.erase(exec.begin() + slash + 1, exec.end()); // Erase filename

	if (chdir(exec.c_str()) == -1)
		throw std::runtime_error(concat("chdir()", error(errno)));

	return exec;
}
