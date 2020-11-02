#include "beaconhdrinfo.h"
#include "gtrace.h"

bool BeaconHdrInfo::parse(char* packet, uint32_t size) {
	char* end = packet;
	end += size;
	radiotapHdr_ = PRadiotapHdr(packet);
	le16_t len = radiotapHdr_->len_;
	if ((void*)radiotapHdr_ >= (void*)end) {
		GTRACE("invalid pointer %p %p\n", (void*)radiotapHdr_, (void*)end);
		return false;
	}
	if (len != sizeof(RadiotapHdr) && len != 18 && len != 13) {
		GTRACE("invalid radiotap header len %u %p %p\n", len, (void*)radiotapHdr_, (void*)end);
		return false;
	}

	Dot11Hdr* dot11Hdr = PDot11Hdr(packet + radiotapHdr_->len_);
	if (dot11Hdr->typeSubtype() != Dot11Hdr::Beacon) return false;
	beaconHdr_ = PBeaconHdr(dot11Hdr);
	BeaconHdr::TaggedParameters::Tag* tag = &beaconHdr_->tagged_.tag_;
	while (true) {
		if ((void*)tag >= (void*)end) {
			GTRACE("tag=%p end=%p\n", tag, end);
			exit(-1);
		}
		if (tag->num_ == BeaconHdr::tagTrafficIndicationMap) {
			tim_ = BeaconHdr::PTrafficIndicationMap(tag);
			return true;
		}
		tag = tag->next();
	}
	return false;
}
