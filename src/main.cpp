#include "core/client.h"
#include "core/config.h"
#include "core/keys.h"
#include "core/server.h"
#include "core/tun.h"
#include "main.h"
#include "socket/udp_socket.h"
#include "type/string.h"
#include "util/logger.h"
#include "util/path.h"
#include "util/system.h"

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

Mode mode = CLIENT;

String interface_name(0UL);

const UDPSocket main_socket;

const Keys* static_keys = nullptr;

const TUN* tun = nullptr;

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

    /* Hadnle the config */
    if (handle_config(arg) == -1) return -1;

    /* If there is a client */
    if (mode == CLIENT) return run_client();

    /* If there is a server */
    return run_server();
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
    /* Create the keys pair */
    const Keys keys;

    /* Create a buffer for the base64 key representations */
    const unsigned long base64_size = sodium_base64_encoded_len(
        crypto_scalarmult_BYTES,
        sodium_base64_VARIANT_ORIGINAL
    );
    UniqPtr<char[]> base64_buffer = new char[base64_size + 1];
    base64_buffer[base64_size] = '\0';

    /* Convert the secret key to the base64 form */
    sodium_bin2base64(base64_buffer, base64_size,
                      keys.Secret(), crypto_scalarmult_SCALARBYTES,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 secret key representation */
    printf("Secret key: %s\n", base64_buffer.Get());

    /* Convert the public key to the base64 form */
    sodium_bin2base64(base64_buffer, base64_size,
                      keys.Public(), crypto_scalarmult_BYTES,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 public key representation */
    printf("Public key: %s\n", base64_buffer.Get());

    /* Return the success code */
    return 0;
}

static int pubkey() {
    /* Create a buffer for the base64 key representations */
    const unsigned long base64_size = sodium_base64_encoded_len(
        crypto_scalarmult_BYTES,
        sodium_base64_VARIANT_ORIGINAL
    );
    UniqPtr<char[]> base64_buffer = new char[base64_size + 1];
    base64_buffer[base64_size] = '\0';

    /* Read the STDIN */
    if (ISATTY(FILENO(stdin))) printf("Enter the secret key: ");
    if (fgets(base64_buffer, (int)base64_size, stdin) == nullptr) {
        FATAL_LOG("Failed to read the STDIN");
        return -1;
    }

    /* Get the public pair of the secret key */
    const Keys keys(base64_buffer);

    /* Convert the public key to the base64 form */
    sodium_bin2base64(base64_buffer, base64_size,
                      keys.Public(), crypto_scalarmult_BYTES,
                      sodium_base64_VARIANT_ORIGINAL);

    /* Print the base64 public key representation */
    printf("%s\n", base64_buffer.Get());

    /* Return the success code */
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
    char current_section[16] = "\0";;
    while (config.getline(line_buffer, BUFFER_SIZE)) {
        /* Delete the comments */
        {
            char* comment_ptr = strchr(line_buffer, '#');
            if (comment_ptr != nullptr) *comment_ptr = '\0';
        }

        /* Get the first non-space char */
        char* line_ptr = line_buffer;
        while(*line_ptr == ' ') ++line_ptr;

        /* Skip the blank lines */
        if (*line_ptr == '\0') continue;

        /* Trim spaces at the end */
        {
            char* line_end = line_ptr + strlen(line_ptr);
            while (*--line_end == ' ') *line_end = '\0';
        }

        /* If there is a section line */
        if (*line_ptr == '[') {
            /* Save the section name */
            sscanf(line_ptr, "[%15[^]]]", current_section);
            TRACE_LOG("Reading the config section [%s]", current_section);
            continue;
        }

        /* If there isn't any section */
        if (*current_section == '\0') continue;

        /* If there is a 'Peers' section */
        if (strcmp(current_section, "Peers") == 0) {
            /* Decode and save the base64 */
            unsigned char* public_key =
                new unsigned char[crypto_scalarmult_BYTES];
            sodium_base642bin(public_key, crypto_scalarmult_BYTES,
                              line_ptr, strlen(line_ptr),
                              nullptr, nullptr, nullptr,
                              sodium_base64_VARIANT_ORIGINAL);
            Server::SavePeer(public_key);
            continue;
        }

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

        /* Save the parameter */
        TRACE_LOG("%s = %s", parameter_key, parameter_value);
        if (strcmp(current_section, "Interface") == 0) {
            if (strcmp(parameter_key, "PrivateKey") == 0)
                Config::Interface::private_key = parameter_value;
            else if (strcmp(parameter_key, "Address") == 0)
                Config::Interface::address = parameter_value;
            else if (strcmp(parameter_key, "Listen") == 0)
                Config::Interface::listen = parameter_value;
            else if (strcmp(parameter_key, "MTU") == 0)
                Config::Interface::mtu = parameter_value;
            else if (strcmp(parameter_key, "PreUp") == 0)
                Config::Interface::pre_up = parameter_value;
            else if (strcmp(parameter_key, "PostUp") == 0)
                Config::Interface::post_up = parameter_value;
            else if (strcmp(parameter_key, "PreDown") == 0)
                Config::Interface::pre_down = parameter_value;
            else if (strcmp(parameter_key, "PostDown") == 0)
                Config::Interface::post_down = parameter_value;
        } else if (strcmp(current_section, "Server") == 0) {
            if (strcmp(parameter_key, "PublicKey") == 0)
                Config::Server::public_key = parameter_value;
            else if (strcmp(parameter_key, "Endpoint") == 0)
                Config::Server::endpoint = parameter_value;
        }
    }

    /* Check the private key */
    if (*(const char*)Config::Interface::private_key == '\0') {
        FATAL_LOG("There is no private key in the config");
        return -1;
    }

    /* Save the keys pair */
    static_keys = new Keys((const char*)Config::Interface::private_key);

    /* Init the main socket for all future connections */
    main_socket.Bind({
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)(int)Config::Interface::listen),
        .sin_addr = INADDR_ANY
    });

    /* Set the tune name and return the success code */
    interface_name = config_path.stem().c_str();
    return 0;
}

static int run_client() {
    /* Block the thread by the socket for no more than 6 seconds */
    constexpr int seconds_to_wait = 6;
#ifdef _WIN64
    constexpr DWORD time = seconds_to_wait * 1000;
#else
    constexpr timeval time {
        .tv_sec = seconds_to_wait,
        .tv_usec = 0
    };
#endif
    main_socket.SetOption(SO_RCVTIMEO, &time, sizeof(time));

    /* Save the server */
    {
        char buffer[] = "255.255.255.255:65535";
        strcpy(buffer, (const char*)Config::Server::endpoint);
        Client::SaveServer(UDPSocket::GetAddress(buffer),
                           (const char*)Config::Server::public_key);
    }

    /* Perform the handshake with the server */
    Client::PerformHandshakeWithServer();

    /* Up the interface */
    up_interface();
    return 0;
}

static int run_server() {
    /* Up the interface */
    up_interface();

    /* Start receiving requests */
    for (;;) {
        /* Buffer for requests and responses */
        char buffer[1500 + 1 + crypto_stream_chacha20_NONCEBYTES];

        /* Recieve the request from a client */
        sockaddr_in from;
        int response_size = main_socket.Receive(buffer, &from);

        /* If there is an error */
        if (response_size == -1) continue;

        /* Handle the package */
        Server::HandlePackage(buffer, from);
    }

    return -1;
}

static void up_interface() {
    /* Exec the PreUp command */
    const char* const pre_up = (const char*)Config::Interface::pre_up;
    if (*pre_up != '\0') System::Exec(pre_up);

    /* Create the interface */
    tun = new TUN(interface_name);
    tun->Up();
    INFO_LOG("Interface [%s] has been created", (const char*)interface_name);

    /* Exec the PostUp command */
    const char* const post_up = (const char*)Config::Interface::post_up;
    if (*post_up != '\0') System::Exec(post_up);
}
