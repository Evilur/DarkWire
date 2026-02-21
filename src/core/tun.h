#pragma once

#include "type/string.h"
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

    void Up() const noexcept;

    void Down() const noexcept;

private:
    const String _tun_name;
    const int _tun_fd;
};
