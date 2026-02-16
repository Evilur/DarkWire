#pragma once

#include "util/class.h"

/**
 * Static class for executing system commands
 * @author Evilur <the.evilur@gmail.com>
 */
class System final {
public:
    PREVENT_INSTANTIATION(System);

    static void Exec(const char* command);
};
