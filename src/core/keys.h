#pragma once

#include "util/class.h"

/**
 * Storage for the secret and public keys
 * @author Evilur <the.evilur@gmail.com>
 */
class Keys final {
public:
    ALLOW_COPY_ALLOW_MOVE(Keys);

    static constexpr int KEY_SIZE = 32;

    explicit Keys() noexcept;

    explicit Keys(const char* base64_secret_key) noexcept;

    ~Keys() = default;

    [[nodiscard]] const unsigned char* Secret() const noexcept;

    [[nodiscard]] const unsigned char* Public() const noexcept;

private:
    unsigned char _sk[KEY_SIZE];
    unsigned char _pk[KEY_SIZE];
};
