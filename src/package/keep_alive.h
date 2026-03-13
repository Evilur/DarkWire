#pragma once

#include "package_type.h"
#include "util/macro.h"

#include <cstring>
#include <sodium.h>

struct KeepAlive final {
    struct {
        PackageType type;
    } __attribute__((packed)) header;
    char data[5];

    explicit KeepAlive() noexcept;
} __attribute__((packed));

FORCE_INLINE KeepAlive::KeepAlive() noexcept {
    header.type = KEEPALIVE;
    memcpy(data, "ALIVE", 5);
}
