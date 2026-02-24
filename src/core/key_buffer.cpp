#include "key_buffer.h"

#include <cstring>
#include <sodium.h>

KeyBuffer::KeyBuffer(const unsigned char* const ptr) noexcept : _ptr(ptr) { }

bool KeyBuffer::operator==(const KeyBuffer& other) const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) == 0;
}

bool KeyBuffer::operator!=(const KeyBuffer& other) const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) != 0;
}

const unsigned char* KeyBuffer::Get() const noexcept { return _ptr; }
