#pragma once
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>

namespace fs = std::filesystem;

class UnitTest final {
public:
    explicit UnitTest(const char* title);

    template<typename F>
    void Run(const char* title, F func);

private:
    unsigned short _counter = 1;

    static inline unsigned short _block_counter = 1;
    static inline const char* _current_block_title = nullptr;
};

template <typename F> void UnitTest::Run(const char* title, F func) {
    /* Print the number of the test */
    printf("\033[34mUnit test #%hu: %s ", _counter++, title);
    fflush(stdout);

    /* Create a temporary file to store the current output */
    char filename[strlen(_current_block_title) +
                  strlen(title) +
                  sizeof("-.result")];
    snprintf(filename, sizeof(filename), "%s.%s.result",
             _current_block_title, title);
    const fs::path temp_file_path = fs::temp_directory_path() / (char*)filename;

    /* Redirect STDOUT and STDERR to the temp file */
    const int real_stdout = dup(STDOUT_FILENO);
    const int real_stderr = dup(STDERR_FILENO);
    const int file_fd = open(temp_file_path.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(file_fd, STDOUT_FILENO);
    dup2(file_fd, STDERR_FILENO);

    /* Exec the function */
    try {
        func();
    } catch (std::exception& e) {
        std::cerr << e.what();
    }

    /* Flush the file */
    std::cout << std::flush;
    std::cerr << std::flush;  //IDK is this necessary

    /* Redirect file descriptors to the terminal again */
    dup2(real_stdout, STDOUT_FILENO);
    dup2(real_stderr, STDERR_FILENO);

    /* Close files */
    close(file_fd);
    close(real_stdout);
    close(real_stderr);

    /* Open two files for reading: current output and right output */
    snprintf(filename, sizeof(filename), "%s/%s.unit",
             _current_block_title, title);
    fs::path right_output_file_path = fs::path("test/units") / (char*)filename;
    std::ifstream current_output(temp_file_path),
                  right_output(right_output_file_path);

    /* Compare two files */
    bool are_equal = true;
    while (!current_output.eof() && !right_output.eof()) {
        /* Read the data to the buffers */
        constexpr unsigned short buffer_size = 1024;
        char current_output_buffer[buffer_size],
             right_output_buffer[buffer_size];
        unsigned int current_output_buffer_len =
            current_output.read(current_output_buffer, buffer_size).gcount(),
                           right_output_buffer_len =
            right_output.read(right_output_buffer, buffer_size).gcount();

        /* Ignore last invisible chars */
        if (current_output.eof()) {
            char last_char =
                current_output_buffer[current_output_buffer_len - 1];
            while (last_char == '\n' || last_char == '\r' || last_char == ' ')
                last_char =
                    current_output_buffer[--current_output_buffer_len - 1];
        }
        if (right_output.eof()) {
            char last_char =
                right_output_buffer[right_output_buffer_len - 1];
            while (last_char == '\n' || last_char == '\r' || last_char == ' ')
                last_char =
                    right_output_buffer[--right_output_buffer_len - 1];
        }

        /* Compare two buffers */
        if (current_output_buffer_len != right_output_buffer_len ||
            memcmp(current_output_buffer, right_output_buffer,
                   current_output_buffer_len) != 0) {
            are_equal = false;
            break;
        }
    }

    /* Close the files */
    current_output.close();
    right_output.close();

    /* Print the result */
    if (are_equal) {
        printf("\033[32m[OK]\n");

        /* Remove the temporary file */
        fs::remove(temp_file_path);
    }
    else {
        printf("\033[31m[ERROR]\n");
        printf("See current output in: %s\n", temp_file_path.c_str());
    }
}