#pragma once

#include "util/class.h"
#include "util/macro.h"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

/**
 * Static class for executing system commands
 * @author Evilur <the.evilur@gmail.com>
 */
class System final {
public:
    PREVENT_INSTANTIATION(System);

    static void Exec(const char* command);
};

FORCE_INLINE void System::Exec(const char* const command) {
    printf("\033[0m[#] %s\n", command);
    system(command);
}
