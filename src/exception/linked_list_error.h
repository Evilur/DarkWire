#pragma once

#include "exception/runtime_error.h"

/**
 * Wrapper class for LinkedList class errors
 * @author Evilur <the.evilur@gmail.com>
 */
class LinkedListError final : public RuntimeError {
    using RuntimeError::RuntimeError;
};
