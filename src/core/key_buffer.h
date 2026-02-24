#pragma once

#include "util/class.h"

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
