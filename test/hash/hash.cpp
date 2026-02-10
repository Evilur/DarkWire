#include "hash.h"
#include "util/hash.h"

#include "../core/unit_test.h"

void hash_unit_test() {
    UnitTest test("Hash");

    test.Run("Value Type", [] {
        const int a = 751;
        int b = 0;
        b = a;
        constexpr int c = 123;
        int d = 0;
        d = c;
        std::cout << (Hash::Get(a) == Hash::Get(b)) << std::endl
                  << (Hash::Get(c) == Hash::Get(d));
    });

    test.Run("Reference", [] {
        constexpr int a = 751;
        const int& b = a;
        int c = 123;
        int& d = c;
        std::cout << (Hash::Get(a) == Hash::Get(b)) << std::endl
                  << (Hash::Get(c) == Hash::Get(d));
    });

    test.Run("Pointer", [] {
        const int a = 751;
        constexpr int b = 123;
        std::cout << (Hash::Get(a) == Hash::Get(&a)) << std::endl
                  << (Hash::Get(b) == Hash::Get(&b));
    });

    test.Run("String", [] {
        constexpr const char* const a = "Test String";
        char b[1024];
        strcpy(b, "Test String");
        std::cout << (Hash::Get(a) == Hash::Get((char*)b)) << std::endl
                  << (Hash::Get("Test String") == Hash::Get("Test String"));
    });

}
