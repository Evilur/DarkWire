#include "global.h"
#include "core/config.h"
#include "core/tun.h"
#include "util/system.h"

#include <thread>

Mode mode = CLIENT;

IpAddress ip_address = { .hb = INADDR_ANY, .nb = INADDR_ANY };

Binmask binmask = { .hb = INADDR_ANY, .nb = INADDR_ANY };

NetworkPrefix network_prefix = { .hb = INADDR_ANY, .nb = INADDR_ANY };

Broadcast broadcast = { .hb = INADDR_ANY, .nb = INADDR_ANY };

unsigned char netmask = 0;

String interface_name(0UL);

TUN* tun = nullptr;

const Keys* static_keys = nullptr;

const UDPSocket main_socket;

void up_interface() {
    /* Exec the PreUp command */
    const char* const pre_up = Config::Interface::pre_up;
    if (*pre_up != '\0') System::Exec(pre_up);

    /* Create the interface */
    tun = new TUN(interface_name);
    tun->Up();

    /* Run the TUN read loop */
    std::thread(&TUN::RunReadLoop, tun).detach();

    /* Exec the PostUp command */
    const char* const post_up = Config::Interface::post_up;
    if (*post_up != '\0') System::Exec(post_up);
}

void calc_net() {
    binmask.hb = (netmask == 0) ? 0x0U : (~0U << (32U - netmask));
    network_prefix.hb = ip_address.hb & binmask.hb;
    broadcast.hb = network_prefix.hb | ~binmask.hb;
    binmask.nb = htonl(binmask.hb);
    network_prefix.nb = htonl(network_prefix.hb);
    broadcast.nb = htonl(broadcast.hb);
}
