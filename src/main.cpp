#include "net/tun.h"
#include "util/logger.h"

#include <exception>

static void on_terminate();

int main(const int argc, const char* const* const argv) {
    /* Bind the 'on_terminate' handler */
    std::set_terminate(on_terminate);

    TUN tun = TUN("dw0");
    return 0;
}

static void on_terminate() {
    /* Get the current exception */
    std::exception_ptr exception = std::current_exception();

    /* If there is no current exceptions */
    if (!exception)
        FATAL_LOG("Terminate called without an active exception");

    /* Print the exception message */
    try {
        std::rethrow_exception(exception);
    } catch (const std::exception& e) {
        FATAL_LOG("Unhandled exception of type '%s':\n%s",
                  typeid(e).name(), e.what());
    } catch (...) { FATAL_LOG("Unhandled unknown exception"); }
}
