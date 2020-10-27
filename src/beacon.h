#pragma once

#include "dot11.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	le8_t frag_:4;
	le16_t seq_:12;

	Mac receiver() { return addr1_;}
	Mac dst() { return addr1_; }
	Mac transmitter() { return addr2_; }
	Mac src() { return addr2_; }
	Mac bssid() { return addr3_; }

	struct FixedParameters {
		le64_t timestamp_; // microsecond
		le16_t beaconInterval_; // millisecond
		le16_t capabilities_;
	} fixed_;

	struct TaggedParameters {
		struct Tag {
			le8_t num_;
			le8_t len_;
			Tag* next() {
				char* res = (char*)this;
				res += sizeof(Tag) + this->len_;
				return PTag(res);
			}
		} tag_;
		typedef Tag *PTag;
	} tagged_;

	// tagged parameter number
	enum: le8_t {
		tagSsidParameterSet = 0,
		tagSupportedRated = 1,
		tagTrafficIndicationMap = 5
	};

	struct TrafficIndicationMap : TaggedParameters::Tag {
		le8_t count_;
		le8_t period_;
		le8_t control_;
		le8_t bitmap_;
	};
	typedef TrafficIndicationMap *PTrafficIndicationMap;
};
typedef BeaconHdr *PBeaconHdr;

#pragma pack(pop)
