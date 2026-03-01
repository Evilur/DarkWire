#pragma once

#include "exception/runtime_error.h"

/**
 * Wrapper class for Dictionary class errors
 * @author Evilur <the.evilur@gmail.com>
 */
class DictionaryError final : RuntimeError {
    using RuntimeError::RuntimeError;
};
