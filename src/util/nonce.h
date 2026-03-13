#pragma once

#include "util/class.h"
#include "util/macro.h"

#include <cstring>
#include <mutex>
#include <sodium.h>

/**
 * Class for generating and encreasing the nonce
 * @author Evilur <the.evilur@gmail.com>
 */
class Nonce final {
public:
    PREVENT_COPY_ALLOW_MOVE(Nonce);

    Nonce() noexcept;

    explicit Nonce(const unsigned char* nonce) noexcept;

    ~Nonce() = default;

    void Copy(unsigned char* buffer) noexcept;

private:
    enum : char { INCREMENT, DECREMENT } _mode;
    unsigned char _nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

    std::mutex _mutex;
};

FORCE_INLINE Nonce::Nonce() noexcept : _mode(INCREMENT) {
    randombytes_buf(_nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

FORCE_INLINE Nonce::Nonce(const unsigned char* nonce)
noexcept : _mode(DECREMENT) {
    memcpy(_nonce, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

FORCE_INLINE void Nonce::Copy(unsigned char* buffer) noexcept {
    std::lock_guard lock(_mutex);
    if (_mode == INCREMENT) {
        for (unsigned char i = crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 1;
             i >= 0; --i) if (++_nonce[i] != 0) break;
    } else {
        for (unsigned char i = crypto_aead_chacha20poly1305_ietf_NPUBBYTES  - 1;
             i >= 0; --i) if (_nonce[i]-- != 0) break;
    }
    memcpy(buffer, _nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}
