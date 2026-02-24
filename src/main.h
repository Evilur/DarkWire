#pragma once

static void on_terminate();

[[nodiscard]] static int print_help();

[[nodiscard]] static int genkey();

[[nodiscard]] static int pubkey();

[[nodiscard]] static int handle_config(const char* name);

[[nodiscard]] static int run_client();

[[nodiscard]] static int run_server();

static void up_interface();
