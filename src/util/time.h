#pragma once

#include "util/macro.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#include <chrono>

/**
 * Static class for getting current time
 * @author Evilur <the.evilur@gmail.com>
 */
#include <cstdint>
class Time final {
public:
    static uint64_t Seconds() noexcept;

    static uint64_t Nanoseconds() noexcept;

    static uint64_t Delta(uint64_t time1, uint64_t time2) noexcept;

    static void Sleep(uint64_t seconds) noexcept;

    static void NanoSleep(uint64_t nanoseconds) noexcept;

    static void WaitUntil(uint64_t timestamp) noexcept;

    static void NanoWaitUntil(uint64_t timestamp) noexcept;
};

FORCE_INLINE uint64_t Time::Seconds() noexcept {
    timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (uint64_t)now.tv_sec;
}

FORCE_INLINE uint64_t Time::Nanoseconds() noexcept {
    timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return ((uint64_t)now.tv_sec * 1'000'000'000ULL) + (uint64_t)now.tv_nsec;
}

FORCE_INLINE uint64_t Time::Delta(const uint64_t time1,
                                  const uint64_t time2) noexcept {
    if (time1 > time2) return time1 - time2;
    return time2 - time1;
}

FORCE_INLINE void Time::Sleep(const uint64_t seconds) noexcept {
#ifdef _WIN32
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
#else
    const timespec timeseconds = {
        .tv_sec = time_t(seconds),
        .tv_nsec = 0L
    };
    nanosleep(&timeseconds, nullptr);
#endif
}

FORCE_INLINE void Time::NanoSleep(const uint64_t nanoseconds) noexcept {
#ifdef _WIN32
    std::this_thread::sleep_for(std::chrono::nanoseconds(nanoseconds));
#else
    const timespec timeseconds = {
        .tv_sec = time_t(nanoseconds / 1'000'000'000L),
        .tv_nsec = long(nanoseconds % 1'000'000'000L)
    };
    nanosleep(&timeseconds, nullptr);
#endif
}

FORCE_INLINE void Time::WaitUntil(const uint64_t timestamp) noexcept {
    const uint64_t current_timestamp = Time::Seconds();
    if (current_timestamp > timestamp) return;
    Time::Sleep(timestamp - current_timestamp);
}

FORCE_INLINE void Time::NanoWaitUntil(const uint64_t timestamp) noexcept {
    const uint64_t current_timestamp = Time::Nanoseconds();
    if (current_timestamp > timestamp) return;
    Time::NanoSleep(timestamp - current_timestamp);
}
