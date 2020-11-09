#include <csignal>
#include <iostream>
#include <string>
#include "gssg.h"

Ssg ssg;

struct Param {
	bool parse(int argc, char** argv) {
		if (argc < 2) {
			usage();
			return false;
		}
		ssg.interface_ = argv[1];
		if (argc < 3)
			return true;
		int i = 2;
		std::string filter = argv[2];
		if (filter.at(0) != '-') {
			ssg.filter_ = filter;
			i++;
		}
		while (i < argc) {
			std::string option = argv[i++];
			if (i >= argc) {
				printf("value not specified\n");
				return false;
			}
			std::string value = argv[i++];
			if (option == "-tc") {
				ssg.option_.tim_.control_ = std::stoi(value);
				printf("ssg.option_.tim_.control=%d\n", ssg.option_.tim_.control_);
			} else if (option == "-tb") {
				ssg.option_.tim_.bitmap_ = std::stoi(value);
				printf("ssg.option_.tim_.bitmap_=%d\n", ssg.option_.tim_.bitmap_);
			} else if (option == "-ai") {
				ssg.option_.adjustInterval_ = std::stoll(value) * 1000000; // sec to usec
				printf("ssg.option_.adjustInterval_=%f\n", double(ssg.option_.adjustInterval_ / 1000000));
			} else if (option == "-smo") {
				ssg.option_.sendMeasureOffset_ = std::stoll(value);
				printf("ssg.option_.sendMeasureOffset_=%f\n", double(ssg.option_.sendMeasureOffset_));
			} else if (option == "-tosd") {
				ssg.option_.tooOldSeqDiff_ = std::stoll(value) * 100000; // sec to usec
				printf("ssg.option_.tooOldSeqDiff_=%f\n", double(ssg.option_.tooOldSeqDiff_) / 100000);
			} else if (option == "-spt") {
				ssg.option_.sendPollingTime_ = Diff(std::stoll(value) * 1000); // usec to nsec
				printf("ssg.option_.sendPollingTime_=%f\n", double(ssg.option_.sendPollingTime_.count()) / 100);
			} else if (option == "-toad") {
				ssg.option_.tooOldApDiff_ = Diff(std::stoll(value) * 1000000000); // sec to nsec
				printf("ssg.option_.tooOldApDiff_=%f\n", double(ssg.option_.tooOldApDiff_.count()) / 1000000000);
			} else if (option == "-cia") {
				ssg.option_.changeIntervalAlpha_ = std::stof(value);
				printf("ssg.option_.changeIntervalAlpha_=%f\n", ssg.option_.changeIntervalAlpha_);
			} else if (option == "-dpn") {
				ssg.option_.debugQosNull_ = (value == "1" || value == "true");
				printf("ssg.option_.debugQosNull_=%s\n", ssg.option_.debugQosNull_ ? "true" : "false");
			} else if (option == "-co") {
				ssg.option_.checkOnly_ = (value == "1" || value == "true");
				printf("ssg.option_.checkOnly_=%s\n", ssg.option_.checkOnly_ ? "true" : "false");
			}
		}
		return true;
	}

	static void usage() {
		printf("syntax: ssg <interface> [<filter>] [options]\n");
		printf("sample: ssg mon0 \"ether host 00:00:00:11:11:11\"\n");
		printf("\n");
		printf("options\n");
		printf("  -tc   <tim control>           (1)\n");
		printf("  -tb   <tim bitmap>            (255)\n");
		printf("  -ai   <adjust interval>       (10 sec)\n");
		printf("  -smo  <send measure offset>   (0 usec)\n");
		printf("  -tosd <too old seq diff>      (10 sec)\n");
		printf("  -spt  <send polling time>     (1000 usec)\n");
		printf("  -toad <too old ap diff>       (15 sec)\n");
		printf("  -cia  <change interval alpha> (0.0)\n");
		printf("  -dqn  <debug qos null>        (0)\n");
		printf("  -co   <check only>            (0)\n");
		printf("\n");
	}
};


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

extern int debug;

int main(int argc, char* argv[]) {
	Param param;
	if (!param.parse(argc, argv))
		return 0;

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
		std::string cmd; std::cin >> cmd;
		if (cmd == "q") break;
		if (cmd == "d") {
			GTRACE("debug=%d\n", debug);
			continue;
		}
		int64_t adjustOffset = std::stoi(cmd);
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
