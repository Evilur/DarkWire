#pragma once

#include "util/class.h"

/**
 * Static class for working with network interface
 * @author Evilur <the.evilur@gmail.com>
 */
class TUN final {
public:
    PREVENT_COPY_AND_MOVE(TUN);

    explicit TUN(const char* name);

    ~TUN() noexcept;

private:
    const int _tun_fd;
};
