#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "type/net_addr.h"

#include <netinet/in.h>

class TUN;

inline enum : char { CLIENT, SERVER } mode = CLIENT;

inline NetAddr local_ip;

inline NetAddr binmask;

inline NetAddr network_prefix;

inline NetAddr broadcast;

inline unsigned char netmask = 0;

inline TUN* tun = nullptr;

inline const Keys* static_keys = nullptr;

inline const UDPSocket main_socket;

static inline void on_terminate();

[[nodiscard]] static int print_help();

[[nodiscard]] static int genkey();

[[nodiscard]] static int pubkey();

[[nodiscard]] static int handle_config(const char* name);

[[nodiscard]] static int run_client();

[[nodiscard]] static int run_server();

void calc_net();
