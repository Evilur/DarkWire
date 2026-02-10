#pragma once

#include "random.h"

template <typename T>
requires std::is_trivially_copyable_v<T>
T Random::Get() {
    /* If there is no random device */
    if (random_device == nullptr)
        random_device = new std::ifstream("/dev/urandom", std::ios::binary);

    /* Get the random data */
    T result { };
    random_device->read((char*)(void*)&result, sizeof(T));

    /* Check for the readded data size */
    if (random_device->gcount() < sizeof(T))
        throw std::runtime_error("Random::Get(): Failed to read random bytes");

    return result;
}
