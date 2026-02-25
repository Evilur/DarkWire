#pragma once

#include "util/class.h"

#include <sodium.h>

/**
 * Class for generating and encreasing the nonce
 * @author Evilur <the.evilur@gmail.com>
 */
class Nonce final {
public:
    ALLOW_COPY_ALLOW_MOVE(Nonce);

    Nonce() noexcept;

    explicit Nonce(const unsigned char* nonce) noexcept;

    ~Nonce() = default;

    void Copy(unsigned char* buffer) noexcept;

private:
    enum : char { INCREMENT, DECREMENT } _mode;
    unsigned char _nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
};
