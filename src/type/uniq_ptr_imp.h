#pragma once

#include "uniq_ptr.h"

template<typename T>
static inline void delete_object(T* const obj) noexcept { delete obj; }

template<typename T>
static inline void delete_array(T* const arr) noexcept { delete[] arr; }

template<typename T, deleter<T> D>
UniqPtrBase<T, D>::UniqPtrBase(T* const ptr) noexcept : _ptr(ptr) { }

template<typename T, deleter<T> D>
UniqPtrBase<T, D>::UniqPtrBase(UniqPtrBase&& other)
noexcept : _ptr(other._ptr) {
    /* Null the other pointer */
    other._ptr = nullptr;
}

template<typename T, deleter<T> D>
UniqPtrBase<T, D>& UniqPtrBase<T, D>::operator=(UniqPtrBase&& other) noexcept {
    /* If there is the same object, do nothing */
    if (this == &other) return *this;

    /* Free the memory */
    (D(_ptr));

    /* Swap the pointers */
    _ptr = other._ptr;

    /* Null the other pointer */
    other._ptr = nullptr;
    return *this;
}

template<typename T, deleter<T> D>
UniqPtrBase<T, D>::~UniqPtrBase() noexcept { (D(_ptr)); }

template<typename T, deleter<T> D>
T* UniqPtrBase<T, D>::Get() noexcept { return _ptr; }

template<typename T, deleter<T> D>
const T* UniqPtrBase<T, D>::Get() const noexcept { return _ptr; }
template<typename T, deleter<T> D>
T& UniqPtrBase<T, D>::operator*() noexcept { return *_ptr; }

template<typename T, deleter<T> D>
const T& UniqPtrBase<T, D>::operator*() const noexcept { return *_ptr; }

template<typename T, deleter<T> D>
UniqPtrBase<T, D>::operator T*() noexcept { return _ptr; }

template<typename T, deleter<T> D>
UniqPtrBase<T, D>::operator const T*() const noexcept { return _ptr; }

template<typename T>
T* UniqPtr<T>::operator->() noexcept { return this->_ptr; }

template<typename T>
const T* UniqPtr<T>::operator->() const noexcept { return this->_ptr; }

template<typename T>
T& UniqPtr<T[]>::operator[](const unsigned long index) noexcept {
    return this->_ptr[index];
}

template<typename T>
const T& UniqPtr<T[]>::operator[](const unsigned long index) const noexcept {
    return this->_ptr[index];
}
