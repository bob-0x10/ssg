#pragma once

#include "dot11hdr.h"

#pragma pack(push, 1)
struct QosNullHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	le8_t frag_:4;
	le16_t seq_:12;
	le16_t qosControl_;

	Mac ra() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac da() { return addr3_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr1_; }
	Mac sta() { return addr2_; }

	static QosNullHdr* check(Dot11Hdr* dot11Hdr, uint32_t size);
};
typedef QosNullHdr *PQosNullHdr;
#pragma pack(pop)
