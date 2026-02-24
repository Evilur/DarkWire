#pragma once

#include "util/class.h"

#include <sodium.h>

/**
 * Storage for the secret and public keys
 * @author Evilur <the.evilur@gmail.com>
 */
class Keys final {
public:
    ALLOW_COPY_ALLOW_MOVE(Keys);

    explicit Keys() noexcept;

    explicit Keys(const char* base64_secret_key) noexcept;

    ~Keys() = default;

    [[nodiscard]] const unsigned char* Secret() const noexcept;

    [[nodiscard]] const unsigned char* Public() const noexcept;

private:
    unsigned char _sk[crypto_scalarmult_SCALARBYTES];
    unsigned char _pk[crypto_scalarmult_BYTES];

public:
    static void SaveStatic(const Keys* keys);

    static const Keys* GetStatic() noexcept;

private:
    static inline const Keys* _static_keys = nullptr;
};
