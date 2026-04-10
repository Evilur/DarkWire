#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "socket/udp_socket.h"
#include "type/net_addr.h"

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

static inline void on_terminate();

[[nodiscard]] static int32_t print_help();

[[nodiscard]] static int32_t genkey();

[[nodiscard]] static int32_t pubkey();

[[nodiscard]] static int32_t handle_config(const char* name);

[[nodiscard]] static int32_t run_client();

[[nodiscard]] static int32_t run_server();

void calc_net();
