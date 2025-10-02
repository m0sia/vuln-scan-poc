#ifndef _LIBKERN_OSBYTEORDER_H_
#define _LIBKERN_OSBYTEORDER_H_

#include <stdint.h>

/*
 * macOS/Darwin byte order functions
 */

#define OSSwapConstInt16(x) \
    ((uint16_t)(((uint16_t)(x) << 8) | ((uint16_t)(x) >> 8)))

#define OSSwapConstInt32(x) \
    ((uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) | \
                (((uint32_t)(x) & 0x00ff0000) >> 8)  | \
                (((uint32_t)(x) & 0x0000ff00) << 8)  | \
                (((uint32_t)(x) & 0x000000ff) << 24)))

#define OSSwapConstInt64(x) \
    ((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
                (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
                (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
                (((uint64_t)(x) & 0x000000ff00000000ULL) >> 8)  | \
                (((uint64_t)(x) & 0x00000000ff000000ULL) << 8)  | \
                (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
                (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
                (((uint64_t)(x) & 0x00000000000000ffULL) << 56)))

static inline uint16_t OSSwapInt16(uint16_t data) {
    return OSSwapConstInt16(data);
}

static inline uint32_t OSSwapInt32(uint32_t data) {
    return OSSwapConstInt32(data);
}

static inline uint64_t OSSwapInt64(uint64_t data) {
    return OSSwapConstInt64(data);
}

/* Host-to-network and network-to-host conversions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define OSSwapHostToBigInt16(x)     OSSwapInt16(x)
#define OSSwapHostToBigInt32(x)     OSSwapInt32(x)
#define OSSwapHostToBigInt64(x)     OSSwapInt64(x)
#define OSSwapBigToHostInt16(x)     OSSwapInt16(x)
#define OSSwapBigToHostInt32(x)     OSSwapInt32(x)
#define OSSwapBigToHostInt64(x)     OSSwapInt64(x)
#define OSSwapHostToLittleInt16(x)  (x)
#define OSSwapHostToLittleInt32(x)  (x)
#define OSSwapHostToLittleInt64(x)  (x)
#define OSSwapLittleToHostInt16(x)  (x)
#define OSSwapLittleToHostInt32(x)  (x)
#define OSSwapLittleToHostInt64(x)  (x)
#else
#define OSSwapHostToBigInt16(x)     (x)
#define OSSwapHostToBigInt32(x)     (x)
#define OSSwapHostToBigInt64(x)     (x)
#define OSSwapBigToHostInt16(x)     (x)
#define OSSwapBigToHostInt32(x)     (x)
#define OSSwapBigToHostInt64(x)     (x)
#define OSSwapHostToLittleInt16(x)  OSSwapInt16(x)
#define OSSwapHostToLittleInt32(x)  OSSwapInt32(x)
#define OSSwapHostToLittleInt64(x)  OSSwapInt64(x)
#define OSSwapLittleToHostInt16(x)  OSSwapInt16(x)
#define OSSwapLittleToHostInt32(x)  OSSwapInt32(x)
#define OSSwapLittleToHostInt64(x)  OSSwapInt64(x)
#endif

#endif /* _LIBKERN_OSBYTEORDER_H_ */