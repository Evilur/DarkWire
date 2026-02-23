#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "core/tun.h"
#include "type/string.h"

enum Mode : char { CLIENT, SERVER };

extern Mode mode;

extern String interface_name;

extern const UDPSocket main_socket;

extern const Keys* static_keys;

extern const TUN* tun;

static void on_terminate();

[[nodiscard]] static int print_help();

[[nodiscard]] static int genkey();

[[nodiscard]] static int pubkey();

[[nodiscard]] static int handle_config(const char* name);

[[nodiscard]] static int run_client();

[[nodiscard]] static int run_server();

static void up_interface();
