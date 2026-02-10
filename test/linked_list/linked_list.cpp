#include "../core/unit_test.h"
#include "container/linked_list.h"

static void fill_list(LinkedList<int>& list);

static void print_list(LinkedList<int>& list);

void linked_list_unit_test() {
    UnitTest test("LinkedList");

    test.Run("Push()", [] {
        LinkedList<int> list;
        fill_list(list);
        print_list(list);
    });

    test.Run("Head()", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << list.Head();
    });

    test.Run("Head() - Exception", [] {
        LinkedList<int> list;
        std::cout << list.Head();
    });

    test.Run("Tail()", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << list.Tail();
    });

    test.Run("Tail() - Exception", [] {
        LinkedList<int> list;
        std::cout << list.Tail();
    });

    test.Run("Pop()", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 8; i++) list.Pop();
        print_list(list);
    });

    test.Run("Pop() - All", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 16; i++) list.Pop();
        print_list(list);
    });


    test.Run("Pop() - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 17; i++) {
            try {
                list.Pop();
            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl;
            }
        }
        print_list(list);
    });

    test.Run("TryPop()", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 8; i++) list.TryPop();
        print_list(list);
    });

    test.Run("TryPop() - All", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 16; i++)
            std::cout << (list.TryPop() ? "true" : "false") << std::endl;
        print_list(list);
    });

    test.Run("TryPop() - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 17; i++)
            std::cout << (list.TryPop() ? "true" : "false") << std::endl;
        print_list(list);
    });

    test.Run("Pop(number)", [] {
        LinkedList<int> list;
        fill_list(list);
        list.Pop(8);
        print_list(list);
    });

    test.Run("Pop(number) - All", [] {
        LinkedList<int> list;
        fill_list(list);
        list.Pop(16);
        print_list(list);
    });

    test.Run("Pop(number) - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        try {
            list.Pop(24);
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << std::endl;
        }
        print_list(list);
    });

    test.Run("TryPop(number)", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryPop(8) << std::endl;;
        print_list(list);
    });

    test.Run("TryPop(number) - All", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryPop(16) << std::endl;;
        print_list(list);
    });

    test.Run("TryPop(number) - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryPop(24) << std::endl;;
        print_list(list);
    });

    test.Run("PopTail()", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 8; i++) list.PopTail();
        print_list(list);
    });

    test.Run("PopTail() - All", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 16; i++) list.PopTail();
        print_list(list);
    });

    test.Run("PopTail() - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 17; i++) {
            try {
                list.PopTail();
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
            }
        }
        print_list(list);
    });

    test.Run("TryPopTail()", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 8; i++)
            std::cout << (list.TryPopTail() ? "true" : "false") << std::endl;
        print_list(list);
    });

    test.Run("TryPopTail() - All", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 16; i++)
            std::cout << (list.TryPopTail() ? "true" : "false") << std::endl;
        print_list(list);
    });

    test.Run("TryPopTail() - Out of index", [] {
        LinkedList<int> list;
        fill_list(list);
        for (int i = 0; i < 17; i++)
            std::cout << (list.TryPopTail() ? "true" : "false") << std::endl;
        print_list(list);
    });

    test.Run("Remove(index, number) - Head", [] {
        LinkedList<int> list;
        fill_list(list);
        list.Remove(0, 8);
        print_list(list);
    });

    test.Run("Remove(index, number) - Center", [] {
        LinkedList<int> list;
        fill_list(list);
        list.Remove(4, 8);
        print_list(list);
    });

    test.Run("Remove(index, number) - Tail", [] {
        LinkedList<int> list;
        fill_list(list);
        list.Remove(8, 8);
        print_list(list);
    });

    test.Run("Remove(index, number) - Exception 1", [] {
        LinkedList<int> list;
        fill_list(list);
        try {
            list.Remove(0, 24);
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << std::endl;
        }
        print_list(list);
    });

    test.Run("Remove(index, number) - Exception 2", [] {
        LinkedList<int> list;
        fill_list(list);
        try {
            list.Remove(8, 24);
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << std::endl;
        }
        print_list(list);
    });

    test.Run("Remove(index, number) - Exception 3", [] {
        LinkedList<int> list;
        fill_list(list);
        try {
            list.Remove(24, 24);
        } catch (const std::runtime_error& e) {
            std::cerr << e.what() << std::endl;
        }
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Head", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(0, 8) << std::endl;
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Center", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(4, 8) << std::endl;
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Tail", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(8, 8) << std::endl;
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Out of index 1", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(0, 24) << std::endl;
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Out of index 2", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(8, 24) << std::endl;
        print_list(list);
    });

    test.Run("TryRemove(index, number) - Out of index 3", [] {
        LinkedList<int> list;
        fill_list(list);
        std::cout << "Result: " << list.TryRemove(24, 24) << std::endl;
        print_list(list);
    });
}

static void fill_list(LinkedList<int>& list) {
    for (int i = 1; i <= 16; i++) list.Push(i);
}

static void print_list(LinkedList<int>& list) {
    /* Print all elements */
    for (const int n : list) std::cout << n << std::endl;

    /* Print the head and the tail */
    std::cout << "---" << std::endl;
    try {
        std::cout << "Head: " << list.Head() << std::endl;
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    try {
        std::cout << "Tail: " << list.Tail() << std::endl;
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}
