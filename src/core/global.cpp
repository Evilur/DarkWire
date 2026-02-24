#include "global.h"

Mode mode = CLIENT;

String interface_name(0UL);

const Keys* static_keys = nullptr;

const UDPSocket main_socket;

const TUN* tun = nullptr;
