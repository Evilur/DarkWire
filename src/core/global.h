#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "core/tun.h"
#include "type/string.h"

#include <netinet/in.h>

enum Mode : char { CLIENT, SERVER };

extern Mode mode;

extern unsigned int ip_address;

extern unsigned int network_prefix;

extern unsigned int broadcast;

extern unsigned char netmask;

extern String interface_name;

extern TUN* tun;

extern const Keys* static_keys;

extern const UDPSocket main_socket;

extern void up_interface();
