#include "util/logger.h"
#include "container/dictionary.h"
#include "type/string.h"
#include "util/path.h"

#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <sodium.h>

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

static int handle_config(const char* name);

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

    /* Init static classes */
    Path::Init();

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
    constexpr const char* const help_message =
        "NAME:\n"
        "\tdw - DarkWire\n\n"
        "DESCRIPTION:\n"
        "\tBuild the Peer2Peer virtual private network (VPN)\n"
        "\tfor fast data transfering between the peers\n"
        "USAGE:\n"
        "\tdw [arguments]\n\n"
        "ARGUMENTS:\n"
        "\t-h, --help\n"
        "\t\tDisplay this help and exit\n"
        "\tgenkey\n"
        "\t\tGenerate a pair of the secret key and its public key\n"
        "\tpubkey\n"
        "\t\tGenerate a public key by the secret key\n"
        "\t<config name>\n"
        "\t\tRun the program using the config file\n";
    printf(help_message);
    return 0;
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

static int handle_config(const char* const name) {
    /* Set the suffix */
    constexpr const char suffix[] = ".conf";

    /* Check if we has the '.conf' suffix */
    const bool has_suffix =
        strcmp(name + strlen(name) - sizeof(suffix) + 1, suffix) == 0;

    /* Build the file name */
    String filename = has_suffix ? String(name) : String(name) + suffix;

    /* Check such a file in the working directory */
    const fs::path config_path = fs::exists((const char*)filename)
        ? (const char*)filename : (Path::CONFIG_DIR / (const char*)filename);

    /* If there is no such a config file anyway */
    if (!fs::exists(config_path)) {
        FATAL_LOG("No such a config file: '%s' or '%s'",
                  (const char*)filename,
                  fs::absolute(config_path).c_str());
        return -1;
    }

    /* Read the config file */
    std::ifstream config = std::ifstream(config_path);
    if (!config.is_open()) {
        FATAL_LOG("Failed to open the config file '%s'",
                  fs::absolute(config_path).c_str());
        return -1;
    }

    /* Read the config file line by line */
    constexpr int BUFFER_SIZE = 1024 * 8;
    char line_buffer[BUFFER_SIZE];
    Dictionary<String, const char*>* current_section_dict = nullptr;
    Dictionary<String, Dictionary<String, const char*>*> config_dict(4);
    while (config.getline(line_buffer, BUFFER_SIZE)) {
        /* Delete the comments */
        char* comment_ptr = strchr(line_buffer, '#');
        if (comment_ptr != nullptr) *comment_ptr = '\0';

        /* Get the first non-space char */
        char* line_ptr = line_buffer;
        while(*line_ptr == ' ') ++line_ptr;

        /* Skip the blank lines */
        if (*line_ptr == '\0') continue;

        /* If there is a section line */
        if (*line_ptr == '[') {
            /* Read the section name */
            char section_name[16];
            sscanf(line_ptr, "[%15[^]]]", section_name);

            /* Put the parameters dictionary to the sectiona dictionary */
            current_section_dict = new Dictionary<String, const char*>(16);
            config_dict.Put(section_name, current_section_dict);
            TRACE_LOG("Reading the config section '%s'", section_name);
            continue;
        }

        /* If there isn't any section */
        if (current_section_dict == nullptr) continue;

        /* Save the parameter key */
        char* const parameter_key = line_ptr;

        /* Get the end of the parameter key */
        char* parameter_key_end = strchr(parameter_key, '=');
        if (parameter_key_end == nullptr) continue;
        char* parameter_value_ptr = parameter_key_end + 1;
        --parameter_key_end;
        while (*parameter_key_end == ' ') *parameter_key_end = '\0';

        /* Save the parameter value to the heap */
        while (*parameter_value_ptr == ' ') ++parameter_value_ptr;
        char* parameter_value = new char[strlen(parameter_value_ptr)];
        strcpy(parameter_value, parameter_value_ptr);

        /* Save the parameter to the dictionary */
        current_section_dict->Put(parameter_key, parameter_value);
        TRACE_LOG("Config parameter has been saved: %s = %s",
                  parameter_key, parameter_value);
    }

    return 0;
}
