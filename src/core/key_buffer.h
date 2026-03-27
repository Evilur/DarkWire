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

    KeyBuffer(const uint8_t *ptr) noexcept;

    ~KeyBuffer() = default;

    bool operator==(const KeyBuffer& other) const noexcept;

    bool operator!=(const KeyBuffer& other) const noexcept;

    [[nodiscard]] const uint8_t* Get() const noexcept;

private:
    const uint8_t* _ptr = nullptr;
};

FORCE_INLINE KeyBuffer::KeyBuffer(const uint8_t* const ptr)
noexcept : _ptr(ptr) { }

FORCE_INLINE bool KeyBuffer::operator==(const KeyBuffer& other)
const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) == 0;
}

FORCE_INLINE bool KeyBuffer::operator!=(const KeyBuffer& other)
const noexcept {
    return memcmp(_ptr, other._ptr, crypto_scalarmult_BYTES) != 0;
}

FORCE_INLINE const uint8_t* KeyBuffer::Get()
const noexcept { return _ptr; }
