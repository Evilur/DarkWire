#include "key.h"

#include <cstring>
#include <sodium.h>

void Key::Put(const char* const base64_secret_key) {
    /* Decode the base64 */
    sodium_base642bin(_sk, key_size,
                      base64_secret_key, strlen(base64_secret_key),
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(_pk, _sk);
}

const unsigned char* Key::SecretKey() noexcept { return _sk; }

const unsigned char* Key::PublicKey() noexcept { return _pk; }
