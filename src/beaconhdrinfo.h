#pragma once

#include <map>
#include "radiotaphdr.h"
#include "beaconhdr.h"

struct BeaconHdrInfo {
	RadiotapHdr* radiotapHdr_;
	BeaconHdr* beaconHdr_;
	BeaconHdr::TrafficIndicationMap* tim_;

	bool parse(char* packet, uint32_t len);
};
typedef BeaconHdrInfo *PBeaconHdrInfo;

struct Key {
	le16_t seq_;
	Key(le16_t seq) : seq_(seq) {}
	bool operator < (const Key& r) const { return seq_ < r.seq_; }
};

struct Val {
	le16_t len_;
	timeval tv_;
	le8_t bitmap_;
	Val(le16_t len, timeval tv, le8_t bitmap) : len_(len), tv_(tv), bitmap_(bitmap) {}
};

typedef std::map<Key, Val> ApMap;

int64_t getDiffTime(timeval tv1, timeval tv2);
