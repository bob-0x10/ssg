#pragma once

#include <map>
#include "gbeaconhdr.h"

struct BeaconHdrInfo {
	BeaconHdr::TrafficIndicationMap* tim_;

	bool parse(BeaconHdr* beaconHdr, uint32_t size);
};
typedef BeaconHdrInfo *PBeaconHdrInfo;

typedef le16_t Key;

struct Val {
	le16_t len_;
	timeval tv_;
	le8_t bitmap_;
	Val(le16_t len, timeval tv, le8_t bitmap) : len_(len), tv_(tv), bitmap_(bitmap) {}
};

typedef std::map<Key, Val> ApMap;

int64_t getDiffTime(timeval tv1, timeval tv2);
