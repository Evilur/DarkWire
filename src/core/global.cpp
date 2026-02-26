#include "global.h"

Mode mode = CLIENT;

unsigned int ip_address = INADDR_ANY;

unsigned char netmask = 0;

String interface_name(0UL);

TUN* tun = nullptr;

const Keys* static_keys = nullptr;

const UDPSocket main_socket;
