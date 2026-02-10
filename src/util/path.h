#pragma once
#include "util/class.h"

#include <filesystem>

/* If we are compiling for Unix based */
#if defined(__unix__) || defined(__unix) || defined(unix)
#include <pwd.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

class Path final {
public:
    PREVENT_INSTANTIATION(Path);

    /* Initialize the class */
    static void Init();

/* If we are compiling for Unix based */
#if defined(__unix__) || defined(__unix) || defined(unix)
    /* Get the user home directory */
    static inline const fs::path HOME_DIR = getpwuid(getuid())->pw_dir;

    /* Get the config directory */
    static inline const fs::path CONFIG_DIR = HOME_DIR / ".config/Ping";

    /* Get the log directory */
    static inline const fs::path LOG_DIR = HOME_DIR / ".cache/Ping";

#endif
    /* Get the config file path */
    static inline const fs::path CONFIG_FILE = CONFIG_DIR / "settings.ini";

    /* Get the config file backup path */
    static inline const fs::path CONFIG_FILE_BAK = CONFIG_DIR / "settings.bak";

    /* Get the ultralight log file path */
    static inline const fs::path ULTRALIGHT_LOG = LOG_DIR / "ultralight.log";

    /* Get the basic log file */
    static inline const fs::path LOG_FILE = LOG_DIR / "ping.log";
};
