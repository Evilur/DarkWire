#include "dictionary.h"
#include "container/dictionary.h"

#include "../core/unit_test.h"

void dictionary_unit_test() {
    UnitTest test("Dictionary");
    constexpr int num_str_size = 16;
    constexpr const char* const num_str[] = {
        "one", "two", "three", "four",
        "five", "six", "seven", "eight",
        "nine", "ten", "eleven", "twelve",
        "thirteen", "fourteen", "fifteen", "sixteen"
    };

    test.Run("Put(int, const char*) - 1", [num_str] {
        Dictionary<int, const char*> dict(num_str_size / 4);
        for (int i = 1; i <= num_str_size; i++) dict.Put(i, num_str[i - 1]);
        for (int i = 1; i <= num_str_size; i++)
            std::cout << dict.Get(i) << '\n';
    });

    test.Run("Put(int, const char*) - 2", [num_str] {
        Dictionary<int, const char*> dict(num_str_size / 2);
        for (int i = 1; i <= num_str_size; i++) dict.Put(i, num_str[i - 1]);
        for (int i = 1; i <= num_str_size; i++)
            std::cout << dict.Get(i) << '\n';
    });

    test.Run("Put(int, const char*) - 3", [num_str] {
        Dictionary<int, const char*> dict(num_str_size);
        for (int i = 1; i <= num_str_size; i++) dict.Put(i, num_str[i - 1]);
        for (int i = 1; i <= num_str_size; i++)
            std::cout << dict.Get(i) << '\n';
    });
}
