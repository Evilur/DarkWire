#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "core/tun.h"
#include "type/net_addr.h"

#include <netinet/in.h>

enum Mode : char { CLIENT, SERVER };

extern Mode mode;

extern NetAddr local_ip;

extern NetAddr binmask;

extern NetAddr network_prefix;

extern NetAddr broadcast;

extern unsigned char netmask;

extern TUN* tun;

extern const Keys* static_keys;

extern const UDPSocket main_socket;

extern void up_interface();

extern void calc_net();
