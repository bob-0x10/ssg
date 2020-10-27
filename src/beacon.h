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
	} fixed_;

	struct TaggedParameters {
		struct Tag {
			le8_t num_;
			le8_t len_;
			uint8_t value_[];
			Tag* next() {
				char* res = (char*)this;
				res += sizeof(Tag) + this->len_;
				return PTag(res);
			}
		} tag_;
		typedef Tag *PTag;
	} tagged_;

	enum: le8_t {
		SsidParameterSet = 0,
		SupportedRated = 1,
		TrafficIndicationMap = 5
	};
};
typedef BeaconHdr *PBeaconHdr;

#pragma pack(pop)
