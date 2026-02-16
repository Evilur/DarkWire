#include "system.h"
#include "type/string.h"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

void System::Exec(const char* const command) {
    printf("\033[0m[#] %s\n", command);
    system(String::Format("exec %s", command));
}
