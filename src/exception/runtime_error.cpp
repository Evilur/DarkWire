#include "runtime_error.h"

#include <cstring>

RuntimeError::~RuntimeError() noexcept { delete[] _message; }

RuntimeError::RuntimeError(const char* const message) :
    _message(new char[strlen(message) + 1]) { strcpy(_message, message); }

const char* RuntimeError::what() const noexcept { return _message; }
