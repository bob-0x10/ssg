#include <csignal>
#include <iostream>
#include "gssg.h"

void usage() {
	printf("syntax: ssg <interface> [<filter>]\n");
	printf("sample: ssg mon0 \"ether host 00:00:00:11:11:11\"\n");
}

Ssg ssg;

void signalHandler(int signo) {
	std::string signal = "unknown";
	switch (signo) {
		case SIGINT: signal = "SIGINT"; break;
		case SIGILL: signal = "SIGILL"; break;
		case SIGABRT: signal = "SIGABRT"; break;
		case SIGFPE: signal = "SIGFPE"; break;
		case SIGSEGV: signal = "SIGSEGV"; break;
		case SIGTERM: signal = "SIGTERM"; break;
		case SIGHUP: signal = "SIGHUP"; break;
		case SIGQUIT: signal = "SIGQUIT"; break;
		case SIGTRAP: signal = "SIGTRAP"; break;
		case SIGKILL: signal = "SIGKILL"; break;
		case SIGBUS: signal = "SIGBUS"; break;
		case SIGSYS: signal = "SIGSYS"; break;
		case SIGPIPE: signal = "SIGPIPE"; break;
		case SIGALRM: signal = "SIGALRM"; break;
	}
	GTRACE("signalHandler signo=%s(%d)\n", signal.c_str(), signo);
	GTRACE("bef closing ssg\n");
	ssg.close();
	GTRACE("aft closing ssg\n");
	exit(0);
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return -1;
	}
	std::string interface = std::string(argv[1]);
	std::string filter = "";
	if (argc == 3) filter = std::string(argv[2]);
	ssg.interface_ = interface;
	ssg.filter_ = filter;

	std::signal(SIGINT, signalHandler);
	std::signal(SIGINT, signalHandler);
	std::signal(SIGILL, signalHandler);
	std::signal(SIGABRT, signalHandler);
	std::signal(SIGFPE, signalHandler);
	std::signal(SIGSEGV, signalHandler);
	std::signal(SIGTERM, signalHandler);
	std::signal(SIGHUP, signalHandler);
	std::signal(SIGQUIT, signalHandler);
	std::signal(SIGTRAP, signalHandler);
	std::signal(SIGKILL, signalHandler);
	std::signal(SIGBUS, signalHandler);
	std::signal(SIGSYS, signalHandler);
	std::signal(SIGPIPE, signalHandler);
	std::signal(SIGALRM, signalHandler);

	if (!ssg.open())
		exit(-1);

	while (true) {
		int64_t adjustOffset = 0; // msec
		std::cin >> adjustOffset;
		if (adjustOffset == 0) break;
		adjustOffset *= 1000000; // nsec
		ssg.apMap_.mutex_.lock();
		for (Ssg::ApMap::iterator it = ssg.apMap_.begin(); it != ssg.apMap_.end(); it++) {
			Ssg::ApInfo& apInfo = it->second;
			apInfo.adjustOffset(Diff(adjustOffset));
		}
		ssg.apMap_.mutex_.unlock();
	}

	GTRACE("bef closing ssg\n");
	ssg.close();
	GTRACE("aft closing ssg\n");
}
