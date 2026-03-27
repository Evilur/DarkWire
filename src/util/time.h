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
};

FORCE_INLINE uint64_t Time::Nanoseconds() noexcept {
    timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return uint64_t((now.tv_sec * 1'000'000'000L) + now.tv_nsec);
}
