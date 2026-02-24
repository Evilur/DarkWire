#include "keys.h"
#include "exception/keys_error.h"

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

void Keys::SaveStatic(const Keys* const keys) {
    if (_static_keys != nullptr)
        throw KeysError("Static keys already have been initialized");
    _static_keys = keys;
}

const Keys* Keys::GetStatic() noexcept { return _static_keys; }
