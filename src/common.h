#pragma once

#include <cassert>
#include <cstdint>
#include "mac.h"
#include "gtrace.h"

typedef uint8_t le8_t;
typedef uint16_t le16_t;
typedef uint32_t le32_t;
typedef uint64_t le64_t;

typedef void *pvoid;
typedef char *pchar;
typedef unsigned char *puchar;

void dump(unsigned char* buf, int size);
