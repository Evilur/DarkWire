#pragma once

#include "type/string.h"
#include "util/class.h"

#include <sodium.h>

class Config final {
public:
    PREVENT_INSTANTIATION(Config);

    struct Interface final {
        static inline String private_key = "";
        static inline String address = "";
        static inline String pre_up = "";
        static inline String post_up = "";
        static inline String pre_down = "";
        static inline String post_down = "";
        static inline short listen = 0;
        static inline int mtu = 1480;
    };

    struct Server final {
        static inline String public_key = "";
        static inline String endpoint = "";
    };
};
