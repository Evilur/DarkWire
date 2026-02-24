#pragma once

#include "socket/udp_socket.h"
#include "core/tun.h"
#include "type/string.h"

enum Mode : char { CLIENT, SERVER };

extern Mode mode;

extern String interface_name;

extern const UDPSocket main_socket;

extern const TUN* tun;
