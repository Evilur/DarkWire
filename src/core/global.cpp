#include "global.h"
#include "core/config.h"
#include "core/tun.h"
#include "util/system.h"

#include <thread>

Mode mode = CLIENT;

unsigned int ip_address = INADDR_ANY;

unsigned int network_prefix = INADDR_ANY;

unsigned int broadcast = INADDR_ANY;

unsigned char netmask = 0;

String interface_name(0UL);

TUN* tun = nullptr;

const Keys* static_keys = nullptr;

const UDPSocket main_socket;

void up_interface() {
    /* Exec the PreUp command */
    const char* const pre_up = (const char*)Config::Interface::pre_up;
    if (*pre_up != '\0') System::Exec(pre_up);

    /* Create the interface */
    tun = new TUN(interface_name);
    tun->Up();

    /* Run the TUN read loop */
    std::thread(&TUN::RunReadLoop, tun).detach();

    /* Exec the PostUp command */
    const char* const post_up = (const char*)Config::Interface::post_up;
    if (*post_up != '\0') System::Exec(post_up);
}
