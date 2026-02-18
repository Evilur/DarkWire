#include "tun.h"
#include "exception/tun_error.h"
#include "util/system.h"

#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

TUN::TUN(const char* const name) :
    /* Open the TUN device */
    _tun_fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC)) {
    if (_tun_fd == -1) throw TunError("Failed to open the TUN device");

    /* Set the name of the new network interface */
    ifreq ifr { };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name == nullptr)
        throw TunError("Name of the tunnel cannot be nullptr");
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    /* Create a new network interface */
    if (ioctl(_tun_fd, TUNSETIFF, (void*)&ifr) == -1)
        throw TunError("Ioctl TUNSETIFF failed");
}

TUN::~TUN() noexcept { close(_tun_fd); }
