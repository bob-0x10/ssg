#pragma once

#include "gradiotaphdr.h"

struct Config {
	struct RadioTapHdrLengthOption {
		le16_t normal_{18};
		le16_t mysending{sizeof(RadiotapHdr)};
		le16_t ignore_{13};
	} rt_;
	struct TrafficIndicationMapOption {
		le8_t control_;
		le8_t bitmap_;
	} tim_;
	int beaconAdjustCount_{3};
	uint64_t tooOldSeqCompareInterval_{10000000000}; // 10 sec
};
extern Config _config;
