#include "path.h"

void Path::Init(){
    /* Create all necessary directories */
    fs::create_directories(CONFIG_DIR);
    fs::create_directories(LOG_DIR);
}