#pragma once

#include "type/string.h"

template <typename T>
unsigned long hash(const T& element) noexcept;

template <>
inline unsigned long hash(const char* const& element) noexcept;

template <>
inline unsigned long hash(const String& element) noexcept;

#include "hash_imp.h"
