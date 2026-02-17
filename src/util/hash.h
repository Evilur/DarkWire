#pragma once

template <typename T>
unsigned long hash(const T& element) noexcept;

template <>
inline unsigned long hash(const char* const& element) noexcept;

template <>
inline unsigned long hash(char* const& element) noexcept;

#include "hash_imp.h"
