#include "nonce.h"

#include <cstring>

Nonce::Nonce() noexcept : _mode(INCREMENT) {
    randombytes_buf(_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}

Nonce::Nonce(const unsigned char* nonce) noexcept : _mode(DECREMENT) {
    memcpy(_nonce, nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}

void Nonce::Copy(unsigned char* buffer) noexcept {
    if (_mode == INCREMENT) {
        for (unsigned char i = crypto_aead_chacha20poly1305_NPUBBYTES - 1;
             i >= 0; --i)
            if (++_nonce[i] != 0)
                break;
    } else {
        for (unsigned char i = crypto_aead_chacha20poly1305_NPUBBYTES  - 1;
             i >= 0; --i)
            if (_nonce[i]-- != 0)
                break;
    }
    memcpy(buffer, _nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
}
