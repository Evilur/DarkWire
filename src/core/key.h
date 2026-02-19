#pragma once

#include "util/class.h"

/**
 * Storage for the secret and public keys
 * @author Evilur <the.evilur@gmail.com>
 */
class Key final {
public:
    PREVENT_INSTANTIATION(Key);

    static void Put(const char* base64_secret_key);

    static const unsigned char* SecretKey() noexcept;

    static const unsigned char* PublicKey() noexcept;

private:
    static constexpr int key_size = 32;
    static inline unsigned char* const _sk = new unsigned char[key_size];
    static inline unsigned char* const _pk = new unsigned char[key_size];
};
