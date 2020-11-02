#include <cassert>
#include <cstdio>
#include <chrono>
#include <iostream>
#include <map>
#include <thread>

#include <unistd.h>
#include <pcap.h>
#include "beaconhdrinfo.h"
#include "gtrace.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

void usage() {
	printf("syntax: beacon-check <interface> <ap-mac>\n");
	printf("sample: beacon-check mon0 00:00:00:11:11:11\n");
}

struct Key {
	le16_t seq_;

	Key(le16_t seq) : seq_(seq) {}

	bool operator < (const Key& r) const {
		return seq_ < r.seq_;
	}
};

struct Val {
	timeval tv_;
	le8_t bitmap_;

	Val(timeval tv,	le8_t bitmap) : tv_(tv), bitmap_(bitmap) {}
};

typedef std::map<Key, Val> ApMap;
ApMap apMap;

int64_t getDiffTime(timeval tv1, timeval tv2) {
	int64_t res = (tv1.tv_sec - tv2.tv_sec) * 1000000;
	res += (tv1.tv_usec - tv2.tv_usec);
	return res;
}

void checkThreadProc(std::string interface, Mac apMac) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.c_str(), errbuf);
		return;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		BeaconHdrInfo bhi;
		if (!bhi.parse(pchar(packet), header->caplen)) continue;
		RadiotapHdr* radiotapHdr = bhi.radiotapHdr_;
		le16_t len = radiotapHdr->len_;
		if (len == 13) continue;

		BeaconHdr* beaconHdr = bhi.beaconHdr_;
		if (beaconHdr->bssid() != apMac) continue;

		Key key(beaconHdr->seq_);
		// GTRACE("seq=%u\n\n", beaconHdr->seq_); // gilgil temp
		Val val(header->ts, bhi.tim_->bitmap_);
		ApMap::iterator it = apMap.find(key);
		if (it == apMap.end()) {
			apMap.insert(std::make_pair(key, val));
		} else{
			Val val2 = it->second;
			if (val.bitmap_ != val2.bitmap_) {
				int64_t diff = getDiffTime(val.tv_, val2.tv_);
				printf("%u %ld %u %u\n", key.seq_, diff, val.bitmap_, val2.bitmap_);
			}
			apMap.erase(it);
		}
	}
	pcap_close(handle);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}
	std::string interface = std::string(argv[1]);
	Mac apMac = Mac(argv[2]);
	std::thread st(checkThreadProc, interface, apMac);
	st.join();
}
