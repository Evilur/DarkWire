#include "global.h"
#include "core/config.h"
#include "core/tun.h"
#include "util/system.h"

Mode mode = CLIENT;

NetAddr ip_address;

NetAddr binmask;

NetAddr network_prefix;

NetAddr broadcast;

unsigned char netmask = 0;

TUN* tun = nullptr;

const Keys* static_keys = nullptr;

const UDPSocket main_socket;

void up_interface() {
    /* Exec the PreUp command */
    const char* const pre_up = Config::Interface::pre_up;
    if (*pre_up != '\0') System::Exec(pre_up);

    /* Up the interface */
    tun->Up();

    /* Exec the PostUp command */
    const char* const post_up = Config::Interface::post_up;
    if (*post_up != '\0') System::Exec(post_up);
}

void calc_net() {
    binmask.SetHostb((netmask == 0) ? 0x0U : (~0U << (32U - netmask)));
    network_prefix.SetHostb(ip_address.hostb & binmask.hostb);
    broadcast.SetHostb(network_prefix.hostb | ~binmask.hostb);
}
