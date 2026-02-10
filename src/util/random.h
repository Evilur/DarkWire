#pragma once

#include "util/class.h"

#include <fstream>

/**
 * Simple wrapper for system random generator
 * @author Evilur the.evilur@gmail.com
 */
class Random final {
public:
    PREVENT_INSTANCE(Random);

    template <typename T>
    requires std::is_trivially_copyable_v<T>
    static T Get();

private:
    static inline std::ifstream* random_device = nullptr;
};

#include "random_imp.h"
