#pragma once

#include "package_type.h"
#include "util/macro.h"

#include <cstring>
#include <sodium.h>

struct KeepAlive final {
    struct {
        PackageType type;
        char buffer[5];
    } __attribute__((packed)) header;

    explicit KeepAlive() noexcept;
} __attribute__((packed));

FORCE_INLINE KeepAlive::KeepAlive() noexcept {
    header.type = KEEPALIVE;
    memcpy(header.buffer, "ALIVE", 5);
}
