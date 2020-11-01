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

#pragma pack(push, 1)
typedef struct {
	RadiotapHdr radiotapHdr;
	BeaconHdr beaconHdr;
	char dummy[1024]; // gilgil temp
} SendStruct;
#pragma pack(pop)

void usage() {
	printf("syntax: timbitmap <interface> <ap-mac>\n");
	printf("sample: timbitmap mon0 00:00:00:11:11:11\n");
}

std::thread* sendThread_{nullptr};
Diff adjust{0};
void sendThreadProc(pcap_t* handle, SendStruct ss, uint32_t writeLen) {
	GTRACE("sendThread beg handle=%p\n", handle);
	const u_char* p = (const u_char*)&ss;
	BeaconHdr* beaconHdr = PBeaconHdr(p + sizeof(RadiotapHdr));
	Diff interval = Diff(beaconHdr->fixed_.beaconInterval_ * 1024 * 1000);
	//interval = Diff(5000000000); // gilgil temp 2020.11.01
	GTRACE("interval=%ld\n", interval.count());

	Diff diff;
	//std::this_thread::sleep_for(interval);
	Clock last = Timer::now();
	while (true) {
		beaconHdr->seq_ += 1;
		//GTRACE("seq=%u\n", beaconHdr->seq_);
		for (int i = 0; i < 1; i++) {
			int res = pcap_sendpacket(handle, (const u_char*)p, writeLen);
			if (res != 0) {
				GTRACE("pacp_sendpacket return %d - %s handle=%p writeLen=%u\n", res, pcap_geterr(handle), handle, writeLen);
				exit(-1);
			}
			//static bool first=true;
			//if (first) {
			//	usleep(4000000);
			//	first = false;
			//}
		}
		Clock now = Timer::now();
		diff = now - last;
		Diff sleepTime = interval - diff;
		if (adjust != Diff(0)) {
			sleepTime += adjust;
			GTRACE("diff=%ld adjust=%ld sleepTime=%ld\n", diff.count(), adjust.count(), sleepTime.count());
			now += adjust;
			adjust = Diff(0);
		}
		//GTRACE("diff=%ld sleepTime=%ld\n", diff.count(), sleepTime.count());
		std::this_thread::sleep_for(sleepTime);
		//usleep(sleepTime.count() / 1000);
		last = Timer::now();
	}
	GTRACE("sendThread end\n");
}

void scanThreadProc(std::string interface, Mac apMac) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.c_str(), errbuf);
		return;
	}

	typedef enum {
		Finding,
		Adjusting
	} Status;

	Status status = Finding;
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
		if (len == sizeof(RadiotapHdr) || len == 13) continue;

		BeaconHdr* beaconHdr = bhi.beaconHdr_;

		if (status == Finding) {
			Mac bssid = beaconHdr->bssid();
			if (!(bssid == apMac)) continue;
			if (bhi.tim_->control_ != 0 || bhi.tim_->bitmap_ != 0) continue;
			bhi.tim_->control_ = 1; // multicast
			bhi.tim_->bitmap_ = 0xFF;

			SendStruct ss;
			char* p = (char*)&ss;
			RadiotapHdr* sendRadiotapHdr = PRadiotapHdr(p);
			sendRadiotapHdr->len_ = sizeof(RadiotapHdr);
			sendRadiotapHdr->pad_ = 0;
			sendRadiotapHdr->ver_ = 0;
			sendRadiotapHdr->present_ = 0;

			BeaconHdr* sendBeaconHdr = PBeaconHdr(p + sendRadiotapHdr->len_);
			uint32_t writeLen = header->caplen - (radiotapHdr->len_ - sizeof(RadiotapHdr));
			memcpy(sendBeaconHdr, beaconHdr, writeLen);
			sendThread_ = new std::thread(sendThreadProc, handle, ss, writeLen); sendThread_->detach();
			//sendThread(handle, ss, writeLen);
			status = Adjusting;
		} else {
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
	std::thread st(scanThreadProc, interface, apMac);


	while (true) {
		double d;
		std::cin >> d;
		int64_t i = d * 1000000000;
		adjust = Diff(i);
	}

	st.join();
}
