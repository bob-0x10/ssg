#pragma once

#include <map>
#include "gbeaconhdr.h"

struct BeaconHdrInfo {
	BeaconHdr::TrafficIndicationMap* tim_;

	bool parse(BeaconHdr* beaconHdr, uint32_t size);
};
typedef BeaconHdrInfo *PBeaconHdrInfo;

typedef le16_t Key;


