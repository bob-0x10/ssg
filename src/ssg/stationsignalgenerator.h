#pragma once

#include <atomic>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include "beaconhdr.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

struct StationSignalGenerator {
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
	typedef std::unordered_map<le16_t/*seq*/, SeqInfo> SecMap;

	struct ApInfo {
		SendBeaconFrame sendBeaconFrame_;
		std::atomic<Diff> sendInterval_;

		SecMap secMap_;

		std::atomic<Diff> adjustOffset_{Diff(0)};
		std::atomic<Diff> adjustInterval_{Diff(0)};

		void adjustOffset(Diff offset);
		void adjustInterval(Diff interval);
	};

	struct ApMap : std::unordered_map<Mac, ApInfo>  {
		Diff getMinNextTime();
	};
	ApMap apMap_;

};
