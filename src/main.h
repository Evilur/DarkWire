#pragma once

#include "core/keys.h"
#include "core/tun.h"
#include "socket/udp_socket.h"
#include "type/string.h"

#include <sodium.h>

#ifdef _WIN32
    #include <io.h>
    #define ISATTY _isatty
    #define FILENO _fileno
#else
    #include <unistd.h>
    #define ISATTY isatty
    #define FILENO fileno
#endif

inline String interface_name = "";

inline sockaddr_in server;

inline const TUN* tun = nullptr;

inline const UDPSocket main_socket;

inline const Keys* static_keys = nullptr;

static void on_terminate();

[[nodiscard]] static int print_help();

[[nodiscard]] static int genkey();

[[nodiscard]] static int pubkey();

[[nodiscard]] static int handle_config(const char* name);

[[nodiscard]] static int run_client();

[[nodiscard]] static int run_server();

static void up_interface();
