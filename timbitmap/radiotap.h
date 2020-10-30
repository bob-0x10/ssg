#pragma once

#include "common.h"

#pragma pack(push, 1)
struct RadiotapHdr {
	le8_t ver_;
	le8_t pad_;
	le16_t len_;
	le32_t present_;
};
typedef RadiotapHdr *PRadiotapHdr;
#pragma pack(pop)
