#pragma once

#include "dot11.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	le8_t frag_:4;
	le16_t seq_:12;

	struct FixedParameters {
		le64_t timestamp_;
		le16_t beaconInterval_;
		le16_t capabilities_;
	} fp;

	struct TaggedParameters {
		struct Tag {
			uint8_t number_;
			uint8_t length_;
			char value_[];
		};
	} tp;
};
typedef BeaconHdr *PBeaconHdr;

#pragma pack(pop)
