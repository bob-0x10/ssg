#pragma once

#include <atomic>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <thread>

#include <pcap.h>
#include "gbeaconhdr.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

struct Ssg { // Station Signal Generator
	typedef struct {
		RadiotapHdr radiotapHdr;
		BeaconHdr beaconHdr;
		char dummy[8192]; // enough size for beacon frame
	} SendBeaconFrame;

	struct SeqInfo {
		timeval tv_;
		le8_t control_;
		le8_t bitmap_;
	};
	typedef std::unordered_map<le16_t/*seq*/, SeqInfo> SeqMap;

	struct ApInfo {
		SendBeaconFrame sendBeaconFrame_;
		std::atomic<Diff> sendInterval_{Diff(0)};

		SeqMap secMap_;

		std::atomic<Diff> adjustOffset_{Diff(0)};
		std::atomic<Diff> adjustInterval_{Diff(0)};

		void adjust(Diff offset, Diff interval);
	};

	struct ApMap : std::unordered_map<Mac, ApInfo>  {
		std::mutex mutex_;
		Diff getMinNextTime();
	};
	ApMap apMap_;

	bool open(std::string devName);
	bool close();

	std::thread* sendThread_{nullptr};
	static void sendThread(Ssg* ssg);

	std::thread* scanThread_{nullptr};
	static void scanThreadProc(Ssg* ss);
};
