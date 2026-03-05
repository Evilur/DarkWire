#pragma once

#include <sodium.h>

inline void hkdf(unsigned char* derived_key,
                 const unsigned char* salt,
                 const unsigned char* shared);

inline void hkdf(unsigned char* derived_key,
                 const unsigned char* const salt,
                 const unsigned char* const shared) {
    /* Extract: HMAC(salt/nullptr, shared) */
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, salt,
                                salt != nullptr ? crypto_scalarmult_BYTES : 0);
    crypto_auth_hmacsha256_update(&state, shared, crypto_scalarmult_BYTES);
    crypto_auth_hmacsha256_final(&state, prk);

    /* Expand: HMAC(prk, 0x01) */
    unsigned char c = 1;
    crypto_auth_hmacsha256_init(&state, prk, crypto_scalarmult_BYTES);
    crypto_auth_hmacsha256_update(&state, &c, 1);
    crypto_auth_hmacsha256_final(&state, derived_key);

    /* Free */
    sodium_memzero(prk, sizeof(prk));
}
