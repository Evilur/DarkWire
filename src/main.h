#pragma once

#include <netinet/in.h>

static inline void on_terminate();

[[nodiscard]] static inline int print_help();

[[nodiscard]] static inline int genkey();

[[nodiscard]] static inline int pubkey();

[[nodiscard]] static inline int handle_config(const char* name);

[[nodiscard]] static inline int run_client();

[[nodiscard]] static inline int run_server();

static inline void run_handle_packages_loop(
    void (*handle_package)(const char* const, const int, const sockaddr_in&)
);
