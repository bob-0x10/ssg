#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <pcap.h>
#include "gbeaconhdr.h"
#include "gqosnullhdr.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

struct Ssg { // Station Signal Generator

	struct {
		struct TrafficIndicationMapOption {
			le8_t control_{1};
			le8_t bitmap_{0xFF};
		} tim_;
		int beaconAdjustCount_{10};
		int64_t tooOldSeqCompareInterval_{10000000000}; // nsec (10 sec)
		int64_t sendPollingTime_{1000000}; // nsec (1 msec)
	} option_;

	#pragma pack(push, 1)
	struct BeaconFrame {
		static const int DummySize = 8192;
		RadiotapHdr radiotapHdr_;
		BeaconHdr beaconHdr_;
		char dummy_[DummySize];
		uint32_t size_;

		bool init(BeaconHdr* beaconHdr, uint32_t size);
		void send(pcap_t* handle);
	};
	#pragma pack(pop)

	struct SeqInfo {
		bool ok_{false};
		timeval tv_;
		le16_t rlen_; // radiotap len;
		le8_t control_;
		le8_t bitmap_;
		void clear() {
			ok_ = false;
			tv_.tv_sec = 0;
			tv_.tv_usec = 0;
			rlen_ = 0;
			control_ = 0;
			bitmap_ = 0;
		}
	};
	struct SeqInfos {
		bool isOk() { return realInfo_.ok_ && sendInfo_.ok_; }
		SeqInfo realInfo_;
		SeqInfo sendInfo_;
	};

	struct SeqMap : std::map<le16_t/*seq*/, SeqInfos> {
		int okCount_{0};
		void clear() {
			okCount_ = 0;
			std::map<le16_t , SeqInfos>::clear();
		}
	};

	struct ApInfo {
		BeaconFrame beaconFrame_;
		Diff sendInterval_{Diff(0)}; // atomic
		Clock nextFrameSent_{std::chrono::seconds(0)};
		SeqMap seqMap_;

		Diff adjustOffset_{Diff(0)}; // atomic
		Diff adjustInterval_{Diff(0)}; // atomic
		void adjustOffset(Diff adjustOffset);
		void adjustInterval(Diff adjustInterval);
	};

	struct ApMap : std::unordered_map<Mac, ApInfo>  {
		std::mutex mutex_;
	};
	ApMap apMap_;

	std::string interface_;
	std::string filter_;
	Ssg(std::string interface, std::string filter) {
		interface_ = interface;
		filter_ = filter;
	}

	RadiotapHdr::LenghChecker lc_;
	bool active_{false};
	bool open();
	bool close();

	std::thread* scanThread_{nullptr};
	static void _scanThread(Ssg* ssg);
	void scanThread();

	std::thread* sendThread_{nullptr};
	static void _sendThread(Ssg* ssg);
	void sendThread();

protected:
	void processQosNull(QosNullHdr* qosNullHdr);
	void processAdjust(ApInfo& apInfo, le16_t seq, SeqInfo seqInfo);
	static int64_t getDiffTime(timeval tv1, timeval tv2);
};
