#include "net/tun.h"
#include "util/logger.h"

#include <cstring>
#include <exception>

static void on_terminate();

static int print_help();

static int genkey();

static int pubkey();

static int keypair();

static int handle_config(const char* filename);

int main(const int argc, const char* const* const argv) {
    /* Bind the 'on_terminate' handler */
    std::set_terminate(on_terminate);

    /* If there is no arguments */
    if (argc <= 1) return print_help();

    /* Read the argument */
    const char* const arg = argv[1];
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        return print_help();
    if (strcmp(arg, "genkey") == 0) return genkey();
    if (strcmp(arg, "pubkey") == 0) return pubkey();
    if (strcmp(arg, "keypair") == 0) return keypair();
    return handle_config(arg);
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

static int print_help() {
    return 0;
}

static int genkey() { }

static int pubkey() { }

static int keypair() { }

static int handle_config(const char* const filename) { }
