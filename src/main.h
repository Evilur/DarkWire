#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "type/net_addr.h"
#include "util/macro.h"

#ifdef _WIN32
    #include <io.h>
    #define ISATTY _isatty
    #define FILENO _fileno
#else
    #include <unistd.h>
    #define ISATTY isatty
    #define FILENO fileno
#endif

class TUN;

inline enum : char { CLIENT, SERVER } mode = CLIENT;

inline NetAddr local_ip;

inline NetAddr binmask;

inline NetAddr network_prefix;

inline NetAddr broadcast;

inline uint8_t netmask = 0;

inline TUN* tun = nullptr;

inline const Keys* static_keys = nullptr;

inline const UDPSocket main_socket;

static FORCE_INLINE void on_terminate();

[[nodiscard]] static int32_t print_help();

[[nodiscard]] static int32_t genkey();

[[nodiscard]] static int32_t pubkey();

[[nodiscard]] static int32_t handle_config(const char* name);

[[nodiscard]] static int32_t run_client();

[[nodiscard]] static int32_t run_server();

[[nodiscard]] bool is_package_duplicate(uint64_t sequence_number,
                                        uint64_t& newest_sequence_number,
                                        uint64_t& sequence_bitmask) noexcept;

void calc_net() noexcept;

FORCE_INLINE
bool is_package_duplicate(const uint64_t sequence_number,
                          uint64_t& newest_sequence_number,
                          uint64_t& sequence_bitmask) noexcept {
    /* Newer than the newest seen packet */
    if (sequence_number > newest_sequence_number) {
        const uint64_t delta = sequence_number - newest_sequence_number;
        if (delta >= 64) sequence_bitmask = 1ULL;
        else sequence_bitmask = (sequence_bitmask << delta) | 1ULL;
        newest_sequence_number = sequence_number;
        return false;
    }

    /* Too old: outside the replay window */
    const uint64_t delta = newest_sequence_number - sequence_number;
    if (delta >= 64) return true;

    /* Already seen such a package */
    const uint64_t bit = 1ULL << delta;
    if ((sequence_bitmask & bit) != 0) return true;

    /* If this is the first time we see it */
    sequence_bitmask |= bit;
    return false;
}

FORCE_INLINE void calc_net() noexcept {
    binmask.SetHostb((netmask == 0) ? 0x0U : (~0U << (32U - netmask)));
    network_prefix.SetHostb(local_ip.Hostb() & binmask.Hostb());
    broadcast.SetHostb(network_prefix.Hostb() | ~binmask.Hostb());
}
