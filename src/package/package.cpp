#include "package.h"

Package::Type Package::GetType(const char* const buffer) noexcept {
    /* Get the raw type (first byte) */
    const unsigned char type = *(const unsigned char*)buffer;

    /* If there is in invalid value */
    if (type > TRANSFER_DATA) return INVALID;

    /* If all is ok */
    return (Type)type;
}
