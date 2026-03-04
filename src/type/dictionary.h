#pragma once

#include "linked_list.h"
#include "util/class.h"
#include "exception/dictionary_error.h"
#include "util/equal.h"
#include "util/hash.h"

/**
 * A simple implementation of a hash map
 * @author Evilur <the.evilur@gmail.com>
 * @tparam K Key typename
 * @tparam T Element typename
 * @tparam S Size typename
 */
template <typename K, typename T, typename S = unsigned short>
class Dictionary final {
struct Node;
public:
    PREVENT_COPY_ALLOW_MOVE(Dictionary);

    /**
     * @param capacity Maximum number of elements without resizing
     */
    explicit Dictionary(S capacity) noexcept;

    /**
     * Free the memory
     */
    ~Dictionary() noexcept;

    /**
     * Put an element into the hash map
     * @param key The key that can be used to retrieve the element
     * @param element Element to put into the map
     * @throw DictionaryError If there is already an element with such a key
     */
    void Put(const K& key, const T& element);

    /**
     * Put an element into the hash map
     * @param key The key that can be used to retrieve the element
     * @param element Element to put into the map
     * @throw DictionaryError If there is already an element with such a key
     */
    void Put(const K& key, T&& element);

    /**
     * Get the element from the hash map by the key
     * @param key The key to get the element by
     * @throw DictionaryError If there is no an element with such a key
     * @return Element with such a key, nullptr if there is no such element
     */
    T& Get(const K& key);

    /**
     * Get the element from the hash map by the key
     * @param key The key to get the element by
     * @throw DictionaryError If there is no an element with such a key
     * @return Element with such a key, nullptr if there is no such element
     */
    const T& Get(const K& key) const;

    /**
     * Check the existence of the element in the hash map
     * @param key The key to check the element by
     * @return true if the element exists, false otherwise
     */
    bool Has(const K& key) const noexcept;

    /**
     * Delete the element from the hash map
     * @param key The key to delete the element by
     */
    void Delete(const K& key);

    /**
     * Iterator to go through the hash map
     */
    class Iterator {
    public:
        explicit Iterator(S index,
                          S capacity,
                          const LinkedList<Node>* lists,
                          LinkedList<Node>::Iterator iterator) noexcept;

        bool operator!=(const Iterator& other) const noexcept;

        Node& operator*() noexcept;

        const Node& operator*() const noexcept;

        Iterator& operator++() noexcept;

    private:
        /**
         * Index of the current bucket in the hash table
         */
        S _index;
        /**
         * Total number of buckets in the hash table
         */
        const S _capacity;
        /**
         * Pointer to the array of linked lists (buckets)
         * that make up the hash table
         */
        const LinkedList<Node>* const _buckets;
        /**
         * Iterator pointing to the current node
         * inside the current bucket's linked list
         */
        LinkedList<Node>::Iterator _iterator;
    };

    /**
     * Get the iterator for the first element
     * @return iterator for the first element
     */
    Iterator begin() const noexcept;

    /**
     * Get the iterator after the last element
     * @return iterator after the last element
     */
    Iterator end() const noexcept;

private:
    /**
     * Node to keep the element and its key in the linked list
     */
    struct Node final {
        K key;
        T element;
    };

    /**
     * A pointer to the dynamic array with linked lists for resolving collisions
     */
    LinkedList<Node>* const _buckets;

    /**
     * A size of the array with linked lists
     */
    const S _capacity;
};

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Dictionary(const S capacity) noexcept :
        _buckets(new LinkedList<Node>[capacity]), _capacity(capacity) { }

template <typename K, typename T, typename S>
Dictionary<K, T, S>::~Dictionary() noexcept { delete[] _buckets; }

template <typename K, typename T, typename S>
void Dictionary<K, T, S>::Put(const K& key, const T& element) {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    for (const Node& node : _buckets[hash])
        if (equal(node.key, key))
            throw DictionaryError(
                "Put(): An element with such a key already exists"
            );

    /* If there is no an element with such a key yet,
     * put the node to the one of the buckets, according to the hash */
    _buckets[hash].Push({ key, element });
}

template <typename K, typename T, typename S>
void Dictionary<K, T, S>::Put(const K& key, T&& element) {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    for (const Node& node : _buckets[hash])
        if (equal(node.key, key))
            throw DictionaryError(
                "Put(): An element with such a key already exists"
            );

    /* If there is no an element with such a key yet,
     * put the node to the one of the buckets, according to the hash */
    _buckets[hash].Push({ key, std::move(element) });
}

template <typename K, typename T, typename S>
T& Dictionary<K, T, S>::Get(const K& key) {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    for (Node& node : _buckets[hash])
        if (equal(node.key, key))
            return node.element;

    /* If there is NOT an element in the linked list, throw an error */
    throw DictionaryError("Get(): no such an element");
}

template <typename K, typename T, typename S>
const T& Dictionary<K, T, S>::Get(const K& key) const {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    for (const Node& node : _buckets[hash])
        if (equal(node.key, key))
            return node.element;

    /* If there is NOT an element in the linked list, throw an error */
    throw DictionaryError("Get(): no such an element");
}

template <typename K, typename T, typename S>
bool Dictionary<K, T, S>::Has(const K& key) const noexcept {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    for (const Node& node : _buckets[hash])
        if (equal(node.key, key))
            return true;

    /* If there is NOT an element in the linked list, return false */
    return false;
}

template <typename K, typename T, typename S>
void Dictionary<K, T, S>::Delete(const K& key) {
    /* Calculate the key hash */
    const S hash = ::hash(key) % _capacity;

    /* Try to get the node from the linked list */
    short index = 0;
    bool has_element = false;
    for (const Node& node : _buckets[hash]) {
        if (equal(node.key, key)) {
            has_element = true;
            break;
        }
        ++index;
    }

    /* Throw an error if there is no an element with such a key */
    if (!has_element)
        throw DictionaryError("Delete(): no such an element");

    /* If all is OK delete the element with such an index from the bucket */
    _buckets[hash].Remove(index);
}

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Iterator Dictionary<K, T, S>::begin() const noexcept {
    /* Iterate over all buckets */
    for (S i = 0; i < _capacity; ++i)
        /* If the current bucket is not empty,
         * return iterator to its first element */
        if (_buckets[i].begin() != _buckets[i].end())
            return Iterator(i, _capacity, _buckets, _buckets[i].begin());

    /* If all buckets are empty, return end() iterator */
    return end();
}

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Iterator Dictionary<K, T, S>::end() const noexcept {
    /* Construct an iterator representing the end position:
     * index == capacity and internal list iterator == nullptr */
    return Iterator(_capacity, _capacity, _buckets,
                    typename LinkedList<Node>::Iterator(nullptr));
}

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Iterator::Iterator(
    const S index,
    const S capacity,
    const LinkedList<Node>* const lists,
    const typename LinkedList<Node>::Iterator iterator
) noexcept : _index(index), _capacity(capacity),
             _buckets(lists), _iterator(iterator) { }

template <typename K, typename T, typename S>
bool Dictionary<K, T, S>::
Iterator::operator!=(const Iterator& other) const noexcept {
    /* If both iterators are "end" iterators, they are equal */
    if (_index == _capacity && other._index == other._capacity) return false;

    /* If they point to different buckets, they are not equal */
    if (_index != other._index) return true;

    /* Otherwise compare underlying list iterators */
    return _iterator != other._iterator;
}

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Node&
Dictionary<K, T, S>::Iterator::operator*() noexcept { return *_iterator; }

template <typename K, typename T, typename S>
const Dictionary<K, T, S>::Node&
Dictionary<K, T, S>::Iterator::operator*() const noexcept { return *_iterator; }

template <typename K, typename T, typename S>
Dictionary<K, T, S>::Iterator&
Dictionary<K, T, S>::Iterator::operator++() noexcept {
    /* If iterator is already at end(), do nothing */
    if (_index == _capacity) return *this;

    /* If still inside a non-empty bucket, stop here */
    if (++_iterator != _buckets[_index].end()) return *this;

    /* Skip empty buckets until a non-empty one is found */
    while (++_index < _capacity) {
        if (_buckets[_index].begin() != _buckets[_index].end()) {
            _iterator = _buckets[_index].begin();
            return *this;
        }
    }

    /* If no more buckets contain elements, set iterator to end() */
    _index = _capacity;
    _iterator = typename LinkedList<Node>::Iterator(nullptr);
    return *this;
}
