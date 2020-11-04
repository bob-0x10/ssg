#include "gradiotaphdr.h"

RadiotapHdr* RadiotapHdr::check(char* p, uint32_t size) {
	RadiotapHdr* radiotapHdr = PRadiotapHdr(p);
	le16_t len = radiotapHdr->len_;
	if (len != sizeof(RadiotapHdr) && len != 18 && len != 13) { // gilgil temp
		char* end = p + size;
		GTRACE("invalid radiotap header len %u %p %p\n", len, (void*)radiotapHdr, (void*)end);
		dump(puchar(p), size);
		return nullptr;
	}
	return radiotapHdr;
}
