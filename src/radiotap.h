#pragma once

#include "common.h"

#pragma pack(push, 1)
struct RadiotapHdr {
	uint8_t version;
	uint8_t pad;
	le16_t len;
	uint32_t present;
};
typedef RadiotapHdr *PRadiotapHdr;
#pragma pack(pop)
