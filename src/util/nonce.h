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

    explicit Nonce(const uint8_t* nonce) noexcept;

    ~Nonce() = default;

    void Copy(uint8_t* buffer) noexcept;

private:
    enum : char { INCREMENT, DECREMENT } _mode;
    uint8_t _nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

    std::mutex _mutex;
};

FORCE_INLINE Nonce::Nonce() noexcept : _mode(INCREMENT) {
    randombytes_buf(_nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

FORCE_INLINE Nonce::Nonce(const uint8_t* nonce)
noexcept : _mode(DECREMENT) {
    memcpy(_nonce, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

FORCE_INLINE void Nonce::Copy(uint8_t* buffer) noexcept {
    std::lock_guard lock(_mutex);
    if (_mode == INCREMENT) {
        for (uint8_t i = crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 1;
             i >= 0; --i) if (++_nonce[i] != 0) break;
    } else {
        for (uint8_t i = crypto_aead_chacha20poly1305_ietf_NPUBBYTES  - 1;
             i >= 0; --i) if (_nonce[i]-- != 0) break;
    }
    memcpy(buffer, _nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}
