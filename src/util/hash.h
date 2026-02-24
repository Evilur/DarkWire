#pragma once

#include "type/string.h"

static unsigned long calculate(const unsigned char* element,
                               unsigned long size) noexcept;

template <typename T>
unsigned long hash(const T& element) noexcept;

template <>
inline unsigned long hash(const char* const& element) noexcept;

template <>
inline unsigned long hash(const String& element) noexcept;

#include "hash_imp.h"
