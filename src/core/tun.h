#pragma once

#include "util/class.h"

/**
 * Class for working with virtual network interface
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
