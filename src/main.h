#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "socket/udp_socket.h"
#include "type/net_addr.h"

#ifdef _WIN32
    #include <io.h>
#pragma pack(push, 1)
    struct iphdr {
        uint8_t  ihl : 4;
        uint8_t  version : 4;
        uint8_t  tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };
#pragma pack(pop)
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

static inline void on_terminate();

[[nodiscard]] static int32_t print_help();

[[nodiscard]] static int32_t genkey();

[[nodiscard]] static int32_t pubkey();

[[nodiscard]] static int32_t handle_config(const char* name);

[[nodiscard]] static int32_t run_client();

[[nodiscard]] static int32_t run_server();

void calc_net();
