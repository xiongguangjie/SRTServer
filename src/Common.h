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

} // namespace SRT

#endif //ZLMEDIAKIT_SRT_COMMON_H