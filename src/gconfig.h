#pragma once

#include "gradiotaphdr.h"

struct Config {

	struct TrafficIndicationMapOption {
		le8_t control_{1};
		le8_t bitmap_{0xFF};
	} tim_;
	int beaconAdjustCount_{10};
	int64_t tooOldSeqCompareInterval_{10000000000}; // 10 sec
	int64_t sendPollingTime_{1000000}; // 1 msec
};
extern Config _config;
