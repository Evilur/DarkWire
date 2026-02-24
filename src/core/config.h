#pragma once

#include "type/linked_list.h"
#include "util/class.h"
#include <sodium.h>

class Config final {
public:
    PREVENT_INSTANTIATION(Config);

    static void Init();

    static void Save();

private:
    class Parameter {
    public:
        PREVENT_COPY_AND_MOVE(Parameter);

        enum Type : char { INTEGER, FLOAT, STRING };

        Parameter(int data);

        Parameter(float data);

        Parameter(const char* data);

        ~Parameter();

        Parameter& operator=(int data);

        Parameter& operator=(float data);

        Parameter& operator=(const char* data);

        explicit operator int() const;

        explicit operator float() const;

        explicit operator const char*() const;

    private:
        const Type _type;
        void* _data = nullptr;
    };

public:
    struct Interface {
        static inline Parameter private_key = "";
        static inline Parameter address = "";
        static inline Parameter listen = 0;
        static inline Parameter mtu = 1420;
        static inline Parameter pre_up = "";
        static inline Parameter post_up = "";
        static inline Parameter pre_down = "";
        static inline Parameter post_down = "";
    };

    struct Server {
        static inline Parameter public_key = "";
        static inline Parameter endpoint = "";
    };
};
