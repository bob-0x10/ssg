#include <cassert>
#include <cstdio>
#include <chrono>
#include <iostream>
#include <thread>

#include <unistd.h>
#include <pcap.h>
#include "gbeaconhdrinfo.h"
#include "gqosnullhdr.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

void usage() {
	printf("syntax: beacon-check <interface> <ap-mac>\n");
	printf("sample: beacon-check mon0 00:00:00:11:11:11\n");
}

ApMap apMap;

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
\
		uint32_t size = header->caplen;
		RadiotapHdr* radiotapHdr = RadiotapHdr::check(pchar(packet), size);
		if (radiotapHdr == nullptr) continue;
		size -= radiotapHdr->len_;

		Dot11Hdr* dot11Hdr = Dot11Hdr::check(radiotapHdr, size);
		if (dot11Hdr == nullptr) continue;

		le8_t typeSubtype = dot11Hdr->typeSubtype();
		if (typeSubtype == Dot11Hdr::QosNull) {
			QosNullHdr* qosNullHdr = QosNullHdr::check(dot11Hdr, size);
			if (qosNullHdr == nullptr) continue;
			if (qosNullHdr->bssid() != apMac) continue;
			printf("                                                                 QosNull bssid=%s sta=%s\n",
				std::string(qosNullHdr->bssid()).c_str(),
				std::string(qosNullHdr->sta()).c_str());
			continue;
		}

		if (typeSubtype != Dot11Hdr::Beacon) continue;

		BeaconHdr* beaconHdr = BeaconHdr::check(dot11Hdr, size);
		if (beaconHdr == nullptr) continue;

		BeaconHdrInfo bhi;
		if (!bhi.parse(beaconHdr, size)) continue;
		le16_t blen = radiotapHdr->len_;
		if (blen == 13) continue;

		if (beaconHdr->bssid() != apMac) continue;

		Key key(beaconHdr->seq_);
		// GTRACE("seq=%u\n\n", beaconHdr->seq_); // gilgil temp
		Val val_new(radiotapHdr->len_, header->ts, bhi.tim_->bitmap_);
		ApMap::iterator it = apMap.find(key);
		if (it == apMap.end()) {
			apMap.insert(std::make_pair(key, val_new));
		} else{
			Val val_old = it->second;
			if (val_old.bitmap_ != val_new.bitmap_) {
				int64_t diff = getDiffTime(val_new.tv_, val_old.tv_); // plus(greater than 0)
				if (diff > 10000000) { // 10 sec ( too old value )
					GTRACE("too old diff %ld\n", diff);
					apMap.erase(it); // delete old
					apMap.insert(std::make_pair(key, val_new)); // insert new
					continue;
				}
				if (val_old.bitmap_ ==0xFF) { // old-my new-real
					// fast
					diff = -diff;
					fprintf(stderr, "fast seq=%u diff=%6ld oldlen=%2u newlen=%2u oldbm=%3u newbm=%3u\n", key, diff, val_old.len_, val_new.len_, val_old.bitmap_, val_new.bitmap_);
				} else {
					// slow
					fprintf(stderr, "slow seq=%u diff=%6ld oldlen=%2u newlen=%2u oldbm=%3u newbm=%3u\n", key, diff, val_old.len_, val_new.len_, val_old.bitmap_, val_new.bitmap_);
				}
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
