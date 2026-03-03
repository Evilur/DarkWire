#include "tun.h"
#include "core/config.h"
#include "core/global.h"
#include "exception/tun_error.h"
#include "util/logger.h"
#include "util/system.h"

#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <unistd.h>

TUN::TUN(const char* const name) : _tun_name(name),
    /* Open the TUN device */
    _tun_fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC)) {
    if (_tun_fd == -1) throw TunError("Failed to open the TUN device");

    /* Set flags */
    ifreq ifr { };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* Set the name of the new network interface */
    if (name == nullptr)
        throw TunError("Name of the tunnel cannot be nullptr");
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    /* Create a new network interface */
    if (ioctl(_tun_fd, TUNSETIFF, &ifr) == -1) {
        FATAL_LOG("Failed to create the virtual interface\n"
                  "Do you have enough permissions?");
        throw TunError("Ioctl TUNSETIFF failed");
    }

    /* IF all is OK */
    System::Exec(String::Format("sysctl -w net.ipv6.conf.%s.disable_ipv6=1",
                                name));
}

TUN::~TUN() noexcept { close(_tun_fd); }

void TUN::Up() noexcept {
    System::Exec(String::Format("ip addr add %s/%hhu dev %s",
                                inet_ntoa({ local_ip.netb }),
                                netmask,
                                _tun_name.CStr()));
    System::Exec(String::Format("ip link set %s up", _tun_name.CStr()));
    INFO_LOG("Interface [%s] is up", _tun_name.CStr());
    _is_up = true;
}

bool TUN::IsUp() const noexcept { return _is_up; }

int TUN::Read(char* const buffer, const unsigned int mtu) const noexcept {
    return (int)read(_tun_fd, buffer, mtu);
}
