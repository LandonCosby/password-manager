#include <iostream>

#include "crypto.h"

int main() {
    if (!pm::init_crypto()) {
        std::cerr << "error: failed to initialize crypto library\n";
        return 1;
    }
    std::cout << "passwordManager 0.1.0\n";
    return 0;
}
