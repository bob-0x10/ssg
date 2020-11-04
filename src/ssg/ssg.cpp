#include <cassert>
#include <cstdio>
#include <chrono>
#include <iostream>
#include <thread>

#include <unistd.h>
#include <pcap.h>
#include "beaconhdrinfo.h"
#include "qosnullhdr.h"


#pragma pack(push, 1)
typedef struct {
	RadiotapHdr radiotapHdr;
	BeaconHdr beaconHdr;
	char dummy[1024]; // gilgil temp
} SendStruct;
#pragma pack(pop)

void usage() {
	printf("syntax: ssg <interface> <ap-mac>\n");
	printf("sample: ssg mon0 00:00:00:11:11:11\n");
}

std::thread* sendThread_{nullptr};
Diff adjust{0};
void sendThreadProc(std::string interface, SendStruct ss, uint32_t writeLen) {
	GTRACE("sendThreadProc beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.c_str(), errbuf);
		return;
	}

	const u_char* p = (const u_char*)&ss;
	BeaconHdr* beaconHdr = PBeaconHdr(p + sizeof(RadiotapHdr));
	Diff interval = Diff(beaconHdr->fix_.beaconInterval_ * 1024 * 1000);
	//interval = Diff(5000000000); // 5 sec // gilgil temp 2020.11.01
	GTRACE("interval=%ld\n", interval.count());

	Diff diff;
	//std::this_thread::sleep_for(interval);
	Clock last = Timer::now();
	while (true) {
		beaconHdr->seq_ += 1;
		for (int i = 0; i < 1; i++) {
			//GTRACE("sending seq=%u\n", beaconHdr->seq_); // gilgil temp
			int res = pcap_sendpacket(handle, p, writeLen);
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
			if (sleepTime.count() < 0) {
				sleepTime = Diff(0);
			}
			//GTRACE("diff=%ld adjust=%ld sleepTime=%ld\n", diff.count(), adjust.count(), sleepTime.count());
			now += adjust;
			adjust = Diff(0);
		}
		//GTRACE("diff=%ld adjust=%ld sleepTime=%ld\n", diff.count(), adjust.count(), sleepTime.count());
		std::this_thread::sleep_for(sleepTime);
		//usleep(sleepTime.count() / 1000); // gilgil temp
		last = Timer::now();
	}
	GTRACE("sendThreadProc end\n");
}

void sendThreadProc2(std::string interface, SendStruct ss, uint32_t writeLen) {
	GTRACE("sendThreadProc2 beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.c_str(), errbuf);
		return;
	}

	const u_char* p = (const u_char*)&ss;
	BeaconHdr* beaconHdr = PBeaconHdr(p + sizeof(RadiotapHdr));
	Diff interval = Diff(beaconHdr->fix_.beaconInterval_ * 1023995);
	//interval = Diff(5000000000); // 5 sec // gilgil temp 2020.11.01
	GTRACE("interval=%ld\n", interval.count());

	//std::this_thread::sleep_for(interval);
	Clock next= Timer::now();
	while (true) {
		Clock now = Timer::now();
		if (adjust != Diff(0)) {
			next += adjust;
			adjust = Diff(0);
		}
		if (now < next) {
			// continue; // gilgil temp 2020.11.04
			Diff remain = next - now;
			remain /= 2;
			remain -= Diff(20000000); // 20 millisecond
			//GTRACE("remain=%ld\n", remain.count());
			if (remain.count() > 0)
				std::this_thread::sleep_for(remain);
			continue;
		}
		beaconHdr->seq_ += 1;
		for (int i = 0; i < 1; i++) {
			//GTRACE("sending seq=%u\n", beaconHdr->seq_); // gilgil temp
			int res = pcap_sendpacket(handle, p, writeLen);
			if (res != 0) {
				GTRACE("pacp_sendpacket return %d - %s handle=%p writeLen=%u\n", res, pcap_geterr(handle), handle, writeLen);
				exit(-1);
			}
		}
		next += interval;
	}
	GTRACE("sendThreadProc2 end\n");
}

void sendThreadProc3(std::string interface, SendStruct ss, uint32_t writeLen) {
	GTRACE("sendThreadProc3 beg\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface.c_str(), errbuf);
		return;
	}

	const u_char* p = (const u_char*)&ss;
	Diff sleepTime = std::chrono::milliseconds(1);
	while (true) {
		int res = pcap_sendpacket(handle, p, writeLen);
		if (res != 0) {
			GTRACE("pacp_sendpacket return %d - %s handle=%p writeLen=%u\n", res, pcap_geterr(handle), handle, writeLen);
			exit(-1);
		}
		std::this_thread::sleep_for(sleepTime);
	}
	GTRACE("sendThreadProc3 end\n");
}

ApMap apMap;
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

		if (beaconHdr->bssid() != apMac) continue;

		if (status == Finding) {
			if (blen == sizeof(RadiotapHdr) || blen == 13) continue;
			if (beaconHdr->bssid() != apMac) continue;
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
			sendThread_ = new std::thread(sendThreadProc2, interface, ss, writeLen); sendThread_->detach(); // gilgil temp 2020.11.03
			// sendThread_ = new std::thread(sendThreadProc2, interface, ss, writeLen); sendThread_->detach();
			status = Adjusting;
		} else {
			continue; // gilgil temp
			if (blen == 13) continue;

			if (beaconHdr->bssid() != apMac) continue;

			Key key(beaconHdr->seq_);
			// GTRACE("seq=%u\n\n", beaconHdr->seq_); // gilgil temp
			Val val_new(radiotapHdr->len_, header->ts, bhi.tim_->bitmap_);
			ApMap::iterator it = apMap.find(key);
			if (it == apMap.end()) {
				apMap.insert(std::make_pair(key, val_new));
			} else {
				static int count = 0;
				if (count++ % 1 == 0) {
					Val val_old = it->second;
					if (val_old.bitmap_ != val_new.bitmap_) {
						int64_t diff = getDiffTime(val_new.tv_, val_old.tv_); // plus(greater than 0)
						if (diff > 10000000) { // 10 sec ( too old value )
							GTRACE("too old diff %ld\n", diff);
							apMap.erase(it); // delete old
							apMap.insert(std::make_pair(key, val_new)); // insert new
							continue;
						}
						//diff = 5; // 0.5 usec // gilgil temp
						if (val_old.bitmap_ ==0xFF) { // old-my new-real
							// fast
							adjust = Diff(diff * 1000);
							fprintf(stderr, "fast seq=%u diff=%6ld oldlen=%2u newlen=%2u oldbm=%3u newbm=%3u\n", key, -diff, val_old.len_, val_new.len_, val_old.bitmap_, val_new.bitmap_);
						} else {
							// slow
							adjust = -Diff(diff * 1000);
							fprintf(stderr, "slow seq=%u diff=%6ld oldlen=%2u newlen=%2u oldbm=%3u newbm=%3u\n", key, diff, val_old.len_, val_new.len_, val_old.bitmap_, val_new.bitmap_);
						}
					}
				}
				apMap.clear();
			}
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
		int64_t i; std::cin >> i;
		i *= 1000000;
		adjust = Diff(i);
	}

	st.join();
}
