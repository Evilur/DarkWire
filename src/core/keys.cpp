#include "keys.h"

#include <cstring>
#include <sodium.h>

Keys::Keys() noexcept {
    /* Generate the random secret key */
    randombytes_buf(_sk, crypto_scalarmult_BYTES);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(_pk, _sk);
}

Keys::Keys(const char* const base64_secret_key) noexcept {
    /* Decode the base64 */
    sodium_base642bin(_sk, crypto_scalarmult_BYTES,
                      base64_secret_key, strlen(base64_secret_key),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(_pk, _sk);
}

const unsigned char* Keys::Secret() const noexcept { return _sk; }

const unsigned char* Keys::Public() const noexcept { return _pk; }
