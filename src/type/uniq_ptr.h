#pragma once

template <typename T>
static void delete_object(T* obj);

template <typename T>
static void delete_array(T* obj);

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

    T* operator->() noexcept;

    const T* operator->() const noexcept;

    T& operator*() noexcept;

    const T& operator*() const noexcept;

private:
    T* _ptr = nullptr;
};

template <typename T>
class UniqPtr final : public UniqPtrBase<T, delete_object> {
    using UniqPtrBase<T, delete_object>::UniqPtrBase;
};

template <typename T>
class UniqPtr<T[]> final : public UniqPtrBase<T, delete_array> {
    using UniqPtrBase<T, delete_array>::UniqPtrBase;
};

#include "uniq_ptr_imp.h"
