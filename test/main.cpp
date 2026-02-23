#include "hash/hash.h"
#include "dictionary/dictionary.h"
#include "linked_list/linked_list.h"
#include "main.h"

Mode mode;

String interface_name(0UL);

const UDPSocket main_socket;

const Keys* static_keys = nullptr;

const TUN* tun = nullptr;

int main() {
    linked_list_unit_test();
    hash_unit_test();
    dictionary_unit_test();
    return 0;
}
