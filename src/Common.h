#ifndef ZLMEDIAKIT_SRT_COMMON_H
#define ZLMEDIAKIT_SRT_COMMON_H
#include <chrono>

namespace SRT
{
using SteadyClock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<SteadyClock>;

using Microseconds = std::chrono::microseconds;
using Milliseconds = std::chrono::milliseconds;

inline int64_t DurationCountMicroseconds( SteadyClock::duration dur){
    return std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
}

inline uint32_t loadUint32(uint8_t *ptr) {
    return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}
inline uint16_t loadUint16(uint8_t *ptr) {
    return ptr[0] << 8 | ptr[1];
}

inline void storeUint32(uint8_t *buf, uint32_t val) {
    buf[0] = val >> 24;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >> 8) & 0xff;
    buf[3] = val & 0xff;
}

inline void storeUint16(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xff;
    buf[1] = val & 0xff;
}

inline void storeUint32LE(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xff;
    buf[1] = (val >> 8) & 0xff;
    buf[2] = (val >> 16) & 0xff;
    buf[3] = (val >>24) & 0xff;
}

inline void storeUint16LE(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xff;
    buf[1] = (val>>8) & 0xff;
}
} // namespace SRT

#endif //ZLMEDIAKIT_SRT_COMMON_H