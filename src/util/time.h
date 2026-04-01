#pragma once

#include "util/macro.h"

#include <chrono>

/**
 * Static class for getting current time
 * @author Evilur <the.evilur@gmail.com>
 */
#include <cstdint>
class Time final {
public:
    static uint64_t Nanoseconds() noexcept;

    static uint64_t Delta(uint64_t time1, uint64_t time2) noexcept;
};

FORCE_INLINE uint64_t Time::Nanoseconds() noexcept {
    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1'000'000'000ULL + (uint64_t)now.tv_nsec;
}

FORCE_INLINE uint64_t Time::Delta(const uint64_t time1,
                                  const uint64_t time2) noexcept {
    if (time1 > time2) return time1 - time2;
    return time2 - time1;
}
