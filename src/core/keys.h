#pragma once

#include "util/class.h"
#include "util/macro.h"

#include <cstring>
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

    [[nodiscard]] const uint8_t* Secret() const noexcept;

    [[nodiscard]] const uint8_t* Public() const noexcept;

private:
    uint8_t _sk[crypto_scalarmult_SCALARBYTES];
    uint8_t _pk[crypto_scalarmult_BYTES];
};

FORCE_INLINE Keys::Keys() noexcept {
    /* Generate the random secret key */
    randombytes_buf(_sk, crypto_scalarmult_BYTES);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(_pk, _sk);
}

FORCE_INLINE Keys::Keys(const char* const base64_secret_key) noexcept {
    /* Decode the base64 */
    sodium_base642bin(_sk, crypto_scalarmult_BYTES,
                      base64_secret_key, strlen(base64_secret_key),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(_pk, _sk);
}

FORCE_INLINE const uint8_t* Keys::Secret() const noexcept { return _sk; }

FORCE_INLINE const uint8_t* Keys::Public() const noexcept { return _pk; }
