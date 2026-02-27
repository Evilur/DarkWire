#pragma once

template <typename T>
inline void delete_object(T* obj) noexcept;

template <typename T>
inline void delete_array(T* arr) noexcept;

template <typename T>
using deleter = void(*)(T*);

/**
 * Simple implementation of the smart unique pointer
 * @author Evilur <the.evilur@gmail.com>
 */
template <typename T, deleter<T> D>
class UniqPtrBase {
public:
    UniqPtrBase(T* ptr) noexcept;

    UniqPtrBase(UniqPtrBase&& other) noexcept;

    UniqPtrBase& operator=(UniqPtrBase&& other) noexcept;

    UniqPtrBase(const UniqPtrBase&) noexcept = delete;

    UniqPtrBase& operator=(const UniqPtrBase&) noexcept = delete;

    ~UniqPtrBase() noexcept;

    T* Get() noexcept;

    const T* Get() const noexcept;

    T& operator*() noexcept;

    const T& operator*() const noexcept;

    operator T*() noexcept;

    operator const T*() const noexcept;

protected:
    T* _ptr = nullptr;
};

template <typename T>
class UniqPtr final : public UniqPtrBase<T, delete_object> {
public:
    using UniqPtrBase<T, delete_object>::UniqPtrBase;

    T* operator->() noexcept;

    const T* operator->() const noexcept;
};

template <typename T>
class UniqPtr<T[]> final : public UniqPtrBase<T, delete_array> {
public:
    using UniqPtrBase<T, delete_array>::UniqPtrBase;

    T& operator[](unsigned long index) noexcept;

    const T& operator[](unsigned long index) const noexcept;
};

#include "uniq_ptr_imp.h"
