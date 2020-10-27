#pragma once

#include "dot11.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1;
	Mac addr2;
	Mac addr3;
	le16_t fragSeq;
	void setSeq(le16_t seq);

	struct WirelessManagement {
		struct FixedParameters {
			le64_t timestamp;
			le16_t beaconInterval;
			le16_t capabilities;
		} fp;

		struct TaggedParameters {
			struct Tag {
				uint8_t number;
				uint8_t length;
				char value[];
			};
		} tp;
	} wm;

};
typedef BeaconHdr *PBeaconHdr;

#pragma pack(pop)
