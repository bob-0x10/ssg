#pragma once

#include "gcommon.h"

#pragma pack(push, 1)
struct RadiotapHdr {
	le8_t ver_;
	le8_t pad_;
	le16_t len_;
	le32_t present_;

	static RadiotapHdr* check(char* p, uint32_t size);
};
typedef RadiotapHdr *PRadiotapHdr;
#pragma pack(pop)
