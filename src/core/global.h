#pragma once

#include "socket/udp_socket.h"
#include "core/keys.h"
#include "core/tun.h"
#include "type/string.h"

#include <netinet/in.h>

enum Mode : char { CLIENT, SERVER };

extern Mode mode;

extern struct IpAddress {
    unsigned int hb;
    unsigned int nb;
} __attribute__((aligned(8))) ip_address;

extern struct Binmask {
    unsigned int hb;
    unsigned int nb;
} __attribute__((aligned(8))) binmask;

extern struct NetworkPrefix {
    unsigned int hb;
    unsigned int nb;
} __attribute__((aligned(8))) network_prefix;

extern struct Broadcast {
    unsigned int hb;
    unsigned int nb;
} __attribute__((aligned(8))) broadcast;

extern unsigned char netmask;

extern String interface_name;

extern TUN* tun;

extern const Keys* static_keys;

extern const UDPSocket main_socket;

extern void up_interface();

extern void calc_net();
