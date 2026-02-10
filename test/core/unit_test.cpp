#include "unit_test.h"

#include <cstdio>
#include <unistd.h>

UnitTest::UnitTest(const char* title) {
    /* Print the number of the unit test block */
    printf("\n\033[35mUnit test block #%hu (%s)\n", _block_counter++, title);
    fflush(stdout);

    /* Save the current block title to the class field */
    _current_block_title = title;
}