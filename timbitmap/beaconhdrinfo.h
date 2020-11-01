#pragma once

#include "radiotaphdr.h"
#include "beaconhdr.h"

struct BeaconHdrInfo {
	RadiotapHdr* radiotapHdr_;
	BeaconHdr* beaconHdr_;
	BeaconHdr::TrafficIndicationMap* tim_;

	bool parse(char* packet, uint32_t len);
};
typedef BeaconHdrInfo *PBeaconHdrInfo;
