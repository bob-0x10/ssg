#include <iostream>
#include <signal.h>
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

	signal(SIGINT, signalHandler);
	signal(SIGINT, signalHandler);
	signal(SIGILL, signalHandler);
	signal(SIGABRT, signalHandler);
	signal(SIGFPE, signalHandler);
	signal(SIGSEGV, signalHandler);
	signal(SIGTERM, signalHandler);
	signal(SIGHUP, signalHandler);
	signal(SIGQUIT, signalHandler);
	signal(SIGTRAP, signalHandler);
	signal(SIGKILL, signalHandler);
	signal(SIGBUS, signalHandler);
	signal(SIGSYS, signalHandler);
	signal(SIGPIPE, signalHandler);
	signal(SIGALRM, signalHandler);

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
