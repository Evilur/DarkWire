#pragma once

#include "package/transfer_data.h"
#include "type/linked_list.h"
#include "type/string.h"
#include "util/class.h"

#include <sodium.h>

class Config final {
public:
    PREVENT_INSTANTIATION(Config);

    struct Interface final {
        static inline String private_key = "";
        static inline String address = "";
        static inline LinkedList<String> pre_up;
        static inline LinkedList<String> post_up;
        static inline LinkedList<String> pre_down;
        static inline LinkedList<String> post_down;
        static inline short listen = 0;
        static inline int mtu = sizeof(TransferData::payload) -
                                crypto_aead_chacha20poly1305_ietf_ABYTES;
    };

    struct Server final {
        static inline String public_key = "";
        static inline String endpoint = "";
    };
};
