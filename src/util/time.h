#pragma once

#include "util/macro.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#include <chrono>
#include <thread>

/**
 * Static class for getting current time
 * @author Evilur <the.evilur@gmail.com>
 */
#include <cstdint>
class Time final {
public:
    static void Run() noexcept;

    static uint64_t Now() noexcept;

    static uint64_t Delta(uint64_t time1, uint64_t time2) noexcept;

    static void Sleep(uint64_t seconds) noexcept;

    static void WaitUntil(uint64_t timestamp) noexcept;

private:
    static inline timespec _now;
};

FORCE_INLINE void Time::Run() noexcept {
    for (;;) {
        /* Get the current time */
        clock_gettime(CLOCK_REALTIME, &_now);

        /* Wait for one sec */
        Sleep(1);
    }
}

FORCE_INLINE uint64_t Time::Now() noexcept {
    return (uint64_t)_now.tv_sec;
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

FORCE_INLINE void Time::WaitUntil(const uint64_t timestamp) noexcept {
    const uint64_t current_timestamp = Time::Now();
    if (current_timestamp > timestamp) return;
    Time::Sleep(timestamp - current_timestamp);
}
