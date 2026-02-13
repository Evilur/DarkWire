#pragma once

#include <netinet/in.h>

template <typename T>
bool equal(const T& e1, const T& e2);

template <>
bool equal(const char* const& e1, const char* const& e2);

template <>
bool equal(const sockaddr_in& e1, const sockaddr_in& e2);

#include "equal_imp.h"
