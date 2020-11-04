#include "gbeaconhdrinfo.h"

bool BeaconHdrInfo::parse(BeaconHdr* beaconHdr, uint32_t size) {
	char* end = pchar(beaconHdr) + size;
	BeaconHdr::Tag* tag = beaconHdr->tag();
	while (true) {
		if ((void*)tag >= (void*)end) {
			GTRACE("beaconHdp=%p tag=%p end=%p\n", pvoid(beaconHdr), tag, end);
			break;
		}
		if (tag->num_ == BeaconHdr::tagTrafficIndicationMap) {
			tim_ = BeaconHdr::PTrafficIndicationMap(tag);
			return true;
		}
		tag = tag->next();
	}
	return false;
}

int64_t getDiffTime(timeval tv1, timeval tv2) {
	int64_t res = (tv1.tv_sec - tv2.tv_sec) * 1000000;
	res += (tv1.tv_usec - tv2.tv_usec);
	return res;
}
