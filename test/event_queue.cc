#include "../include/event_queue.hh"
#include "../include/file_descriptor.hh"

#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <optional>
#include <unistd.h>

using std::array;
using std::chrono::milliseconds;
using std::chrono::system_clock;
using std::chrono_literals::operator""ms;
using std::function;
using std::string;

TEST(EventQueue, add_time_handler) {
	auto start = system_clock::now();
	string order;

	EventQueue eq;
	eq.add_time_handler(start + 3ms, [&] {
		EXPECT_LE(start + 3ms, system_clock::now());
		order += "3";

		eq.add_time_handler(start + 6ms, [&] {
			EXPECT_LE(start + 6ms, system_clock::now());
			order += "6";
		});
	});

	eq.add_time_handler(start + 2ms, [&] {
		EXPECT_LE(start + 2ms, system_clock::now());
		order += "2";

		eq.add_time_handler(start + 4ms, [&] {
			EXPECT_LE(start + 4ms, system_clock::now());
			order += "4";
		});
	});

	eq.add_time_handler(start + 5ms, [&] {
		EXPECT_LE(start + 5ms, system_clock::now());
		order += "5";
	});

	eq.run();
	EXPECT_EQ(order, "23456");
}

TEST(EventQueue, remove_time_handler) {
	auto start = system_clock::now();
	string order;

	EventQueue eq;
	auto hid = eq.add_time_handler(start + 3ms, [&] { FAIL(); });

	eq.add_time_handler(start + 2ms, [&] {
		EXPECT_LE(start + 2ms, system_clock::now());
		order += "2";
		eq.remove_handler(hid);

		eq.add_time_handler(start + 4ms, [&] {
			EXPECT_LE(start + 4ms, system_clock::now());
			order += "4";
		});

		eq.add_ready_handler([&] {
			EXPECT_LE(start + 2ms, system_clock::now());
			order += "r";
		});
	});

	eq.run();
	EXPECT_EQ(order, "2r4");
}

TEST(EventQueue, time_only_fairness) {
	auto start = system_clock::now();
	bool stop = false;

	EventQueue eq;
	eq.add_time_handler(start + 2ms, [&] {
		EXPECT_LE(start + 2ms, system_clock::now());
		stop = true;
	});

	uint64_t looper_iters = 0;
	auto looper = [&](auto&& self) {
		if (stop)
			return;

		++looper_iters;
		if (system_clock::now() > start + 100ms)
			FAIL();

		eq.add_ready_handler([&] { self(self); });
	};

	eq.add_ready_handler([&] { looper(looper); });

	eq.run();
	EXPECT_GT(looper_iters, 10);
}

TEST(EventQueue, file_only_fairness) {
	uint64_t iters_a = 0, iters_b = 0;
	EventQueue eq;

	FileDescriptor fd_a("/dev/zero", O_RDONLY);
	EventQueue::handler_id_t file_a_hid;
	file_a_hid = eq.add_file_handler(fd_a, FileEvent::READABLE, [&](FileEvent) {
		if (iters_b + iters_b > 500)
			return eq.remove_handler(file_a_hid);

		++iters_a;
	});

	FileDescriptor fd_b("/dev/null", O_WRONLY);
	EventQueue::handler_id_t file_b_hid;
	file_b_hid =
	   eq.add_file_handler(fd_b, FileEvent::WRITEABLE, [&](FileEvent) {
		   if (iters_b + iters_b > 500)
			   return eq.remove_handler(file_b_hid);

		   ++iters_b;
	   });

	eq.run();
	EXPECT_EQ(iters_a, iters_b);
}

TEST(EventQueue, time_file_fairness) {
	auto start = system_clock::now();
	uint64_t looper_iters = 0;
	bool stop = false;

	EventQueue eq;
	function<void()> looper = [&] {
		if (stop)
			return;

		++looper_iters;
		if (system_clock::now() > start + 100ms)
			FAIL();

		eq.add_ready_handler(looper);
	};
	eq.add_ready_handler(looper);
	eq.add_time_handler(start + 2ms, [&] {
		EXPECT_LE(start + 2ms, system_clock::now());
		stop = true;
	});

	FileDescriptor fd("/dev/zero", O_RDONLY);
	EventQueue::handler_id_t hid;
	int file_iters = 0;
	hid = eq.add_file_handler(fd, FileEvent::READABLE, [&](FileEvent) {
		if (stop)
			return eq.remove_handler(hid);

		if (system_clock::now() > start + 100ms) {
			FAIL();
			return eq.remove_handler(hid);
		}

		++file_iters;
	});

	eq.run();
	EXPECT_GT(looper_iters, 10);
	EXPECT_GT(file_iters, 4);
}

TEST(EventQueue, full_fairness) {
	auto start = system_clock::now();
	uint64_t iters_a = 0, iters_b = 0;
	bool stop = false;
	EventQueue eq;

	FileDescriptor fd_a("/dev/zero", O_RDONLY);
	EventQueue::handler_id_t file_a_hid;
	file_a_hid = eq.add_file_handler(fd_a, FileEvent::READABLE, [&](FileEvent) {
		if (stop)
			return eq.remove_handler(file_a_hid);

		if (system_clock::now() > start + 100ms) {
			FAIL();
			return eq.remove_handler(file_a_hid);
		}

		++iters_a;
	});

	FileDescriptor fd_b("/dev/null", O_WRONLY);
	EventQueue::handler_id_t file_b_hid;
	file_b_hid =
	   eq.add_file_handler(fd_b, FileEvent::WRITEABLE, [&](FileEvent) {
		   if (stop)
			   return eq.remove_handler(file_b_hid);

		   if (system_clock::now() > start + 100ms) {
			   FAIL();
			   return eq.remove_handler(file_b_hid);
		   }

		   ++iters_b;
	   });

	uint looper_iters = 0;
	function<void()> looper = [&] {
		if (stop)
			return;

		++looper_iters;
		if (system_clock::now() > start + 100ms)
			FAIL();

		eq.add_ready_handler(looper);
	};
	eq.add_ready_handler(looper);
	eq.add_time_handler(start + 2ms, [&] {
		EXPECT_LE(start + 2ms, system_clock::now());
		stop = true;
	});

	eq.run();
	EXPECT_GT(looper_iters, 20);
	EXPECT_GT(iters_a, 20);
	EXPECT_GT(iters_b, 20);
	EXPECT_NEAR(iters_a, iters_b, 1);
}

TEST(EventQueue, file_unready_read_and_close_event) {
	std::array<int, 2> pfd;
	ASSERT_EQ(pipe2(pfd.data(), O_NONBLOCK), 0);
	FileDescriptor rfd(pfd[0]), wfd(pfd[1]);
	std::string buff(10, '\0');

	EventQueue eq;
	auto start = system_clock::now();
	eq.add_time_handler(start + 2ms,
	                    [&] { write(wfd, "Test", sizeof("Test")); });
	eq.add_time_handler(start + 3ms, [&] { (void)wfd.close(); });

	EXPECT_EQ(read(rfd, buff.data(), buff.size()), -1);
	EXPECT_EQ(errno, EAGAIN);

	EventQueue::handler_id_t hid;
	int round = 0;
	std::array expected_events = {FileEvent::READABLE, FileEvent::CLOSED};
	hid = eq.add_file_handler(rfd, FileEvent::READABLE, [&](FileEvent events) {
		EXPECT_EQ(events, expected_events[round++]);
		if (events == FileEvent::CLOSED)
			return eq.remove_handler(hid);

		int rc = read(rfd, buff.data(), buff.size());
		ASSERT_EQ(rc, sizeof("Test"));
		buff.resize(rc - 1);
		ASSERT_EQ(buff, "Test");
	});

	eq.run();
	EXPECT_EQ(round, 2);
}

TEST(EventQueue, file_simultaneous_read_and_close_event) {
	std::array<int, 2> pfd;
	ASSERT_EQ(pipe2(pfd.data(), O_NONBLOCK), 0);
	FileDescriptor rfd(pfd[0]), wfd(pfd[1]);
	write(wfd, "Test", sizeof("Test"));
	(void)wfd.close();

	EventQueue eq;
	EventQueue::handler_id_t hid;
	hid = eq.add_file_handler(rfd, FileEvent::READABLE, [&](FileEvent events) {
		EXPECT_EQ(events, FileEvent::READABLE | FileEvent::CLOSED);
		eq.remove_handler(hid);
	});

	eq.run();
}

// TODO: test adding / removing handler when one is being run -- every case
// where it can be done inside code handling running events
