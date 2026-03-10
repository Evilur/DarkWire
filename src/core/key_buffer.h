#pragma once

#include "util/class.h"
#include "util/macro.h"

#include <cstring>
#include <sodium.h>

/**
 * A wrapper class for the key buffer
 * @author Evilur <the.evilur@gmail.com>
 */
class KeyBuffer final {
public:
    ALLOW_COPY_ALLOW_MOVE(KeyBuffer);

    KeyBuffer(const unsigned char *ptr) noexcept;

    ~KeyBuffer() = default;

    bool operator==(const KeyBuffer& other) const noexcept;

    bool operator!=(const KeyBuffer& other) const noexcept;

    [[nodiscard]] const unsigned char* Get() const noexcept;

private:
    const unsigned char* _ptr = nullptr;
};

FORCE_INLINE KeyBuffer::KeyBuffer(const unsigned char* const ptr)
noexcept : _ptr(ptr) { }

FORCE_INLINE bool KeyBuffer::operator==(const KeyBuffer& other)
const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) == 0;
}

FORCE_INLINE bool KeyBuffer::operator!=(const KeyBuffer& other)
const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) != 0;
}

FORCE_INLINE const unsigned char* KeyBuffer::Get()
const noexcept { return _ptr; }
