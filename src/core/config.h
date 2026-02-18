#pragma once

#include "container/linked_list.h"
#include "type/string.h"
#include "util/class.h"

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

        Parameter(Type type);

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
        static inline Parameter private_key = Parameter(Parameter::STRING);
        static inline Parameter address = Parameter(Parameter::STRING);
        static inline Parameter mtu = Parameter(Parameter::INTEGER);
        static inline Parameter pre_up = Parameter(Parameter::STRING);
        static inline Parameter post_up = Parameter(Parameter::STRING);
        static inline Parameter pre_down = Parameter(Parameter::STRING);
        static inline Parameter post_down = Parameter(Parameter::STRING);
    };

    struct Server {
        static inline Parameter public_key = Parameter(Parameter::STRING);
        static inline Parameter endpoint = Parameter(Parameter::STRING);
    };

    static inline LinkedList<String>* peers = nullptr;
};
