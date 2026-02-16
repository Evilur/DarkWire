#pragma once
#include "util/class.h"

#include <filesystem>

/* If we are compiling for Unix based */
#if defined(__unix__) || defined(__unix) || defined(unix)
#include <pwd.h>
#include <unistd.h>
#endif

/* Create a shorcut for the std::filesystem namespace */
namespace fs = std::filesystem;

class Path final {
public:
    PREVENT_INSTANTIATION(Path);

    /* Initialize the class */
    static void Init();

/* If we are compiling for Unix based */
#if defined(__unix__) || defined(__unix) || defined(unix)
    /* Get the config directory */
    static inline const fs::path CONFIG_DIR = "/etc/darkwire";
#endif
};
