#pragma once

#include "util/class.h"

#include <exception>

/**
 * Wraper exception class for allocation errors
 * @author Evilur the.evilur@gmail.com
 */
class AllocationError final : std::exception {
public:
    PREVENT_COPY_ALLOW_MOVE(AllocationError);

    AllocationError() noexcept;

    ~AllocationError() noexcept override = default;

    [[nodiscard]] const char* what() const noexcept override;

private:
    static constexpr const char* _message = "Allocation error";
};
