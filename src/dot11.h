#pragma once

#include "common.h"

#pragma pack(push, 1)
struct Dot11Hdr {
	uint8_t typeSubtype_;
	uint8_t control_;
	le16_t duration_;

	uint8_t version() { return typeSubtype_ & 0x03; }
	uint8_t type() { return typeSubtype_ & 0x0C; }
	uint8_t subtype() { return typeSubtype_ & 0xF0;}
	uint8_t typeSubtype() { return (type() << 4) | subtype(); }

	// type
	enum: uint8_t {
		Manage = 0,
		Control = 1,
		Data = 2
	};

	// typeSubtype
	enum: uint8_t {
		Beacon = 0x08,
		Acknowledgement = 0x1d
	};
};
typedef Dot11Hdr *PDot11Hdr;
#pragma pack(pop)
