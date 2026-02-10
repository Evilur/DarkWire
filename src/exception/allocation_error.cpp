#include "allocation_error.h"
#include "util/logger.h"

AllocationError::AllocationError() noexcept { FATAL_LOG(_message); }

const char* AllocationError::what() const noexcept { return _message; }
