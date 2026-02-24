#include "global.h"

Mode mode = CLIENT;

String interface_name(0UL);

const UDPSocket main_socket;

const TUN* tun = nullptr;
