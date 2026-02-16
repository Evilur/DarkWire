#include "util/logger.h"

#include <cstring>
#include <exception>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <io.h>
    #define ISATTY _isatty
    #define FILENO _fileno
#else
    #include <unistd.h>
    #define ISATTY isatty
    #define FILENO fileno
#endif

static void on_terminate();

static int print_help();

static int genkey();

static int pubkey();

static int handle_config(const char* filename);

int main(const int argc, const char* const* const argv) {
    /* Bind the 'on_terminate' handler */
    std::set_terminate(on_terminate);

    /* If there is no arguments */
    if (argc <= 1) return print_help();

    /* Init the libsodium */
    if (sodium_init() == -1) {
        FATAL_LOG("Failed to initiate the libsodium");
        return -1;
    }

    /* Read the argument */
    const char* const arg = argv[1];
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        return print_help();
    if (strcmp(arg, "genkey") == 0) return genkey();
    if (strcmp(arg, "pubkey") == 0) return pubkey();
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
    return -1;
}

static int genkey() {
    /* Create buffers for keys */
    constexpr int key_size = 32;
    unsigned char secretkey_buffer[key_size];
    unsigned char publickey_buffer[key_size];

    /* Generate the secret key */
    randombytes_buf(secretkey_buffer, key_size);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(publickey_buffer, secretkey_buffer);

    /* Create a buffer for the base64 key representations */
    const unsigned long base64_size = sodium_base64_encoded_len(
        key_size,
        sodium_base64_VARIANT_ORIGINAL
    );
    char* const base64_buffer = new char[base64_size + 1];
    base64_buffer[base64_size] = '\0';

    /* Convert the secret key to the base64 form */
    sodium_bin2base64(base64_buffer,
                      base64_size,
                      secretkey_buffer,
                      key_size,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 secret key representation */
    printf("Secret key: %s\n", base64_buffer);

    /* Convert the public key to the base64 form */
    sodium_bin2base64(base64_buffer, base64_size,
                      publickey_buffer, key_size,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 public key representation */
    printf("Public key: %s\n", base64_buffer);

    /* Return the success code */
    delete[] base64_buffer;
    return 0;
}

static int pubkey() {
    /* Create buffers for keys */
    constexpr int key_size = 32;
    unsigned char secretkey_buffer[key_size];
    unsigned char publickey_buffer[key_size];

    /* Create a buffer for the base64 key representations */
    const unsigned long base64_size = sodium_base64_encoded_len(
        key_size,
        sodium_base64_VARIANT_ORIGINAL
    );
    char* const base64_buffer = new char[base64_size + 1];
    base64_buffer[base64_size] = '\0';

    /* Read the STDIN */
    if (ISATTY(FILENO(stdin))) printf("Enter the secret key: ");
    if (fgets((char*)base64_buffer, (int)base64_size, stdin) == nullptr) {
        FATAL_LOG("Failed to read the STDIN");
        return -1;
    }

    /* Decode the base64 */
    sodium_base642bin(secretkey_buffer, key_size,
                      base64_buffer, base64_size,
                      nullptr, nullptr, nullptr,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Generate the public key and do a key clamping */
    crypto_scalarmult_base(publickey_buffer, secretkey_buffer);

    /* Convert the public key to the base64 form */
    sodium_bin2base64(base64_buffer, base64_size,
                      publickey_buffer, key_size,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 public key representation */
    printf("%s\n", base64_buffer);

    /* Return the success code */
    delete[] base64_buffer;
    return 0;
}

static int handle_config(const char* const filename) {
    return -1;
}
