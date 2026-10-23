#include "crypto.h"

#include <sodium.h>

namespace pm {

bool init_crypto() {
    // sodium_init returns 1 if it was already initialized, which is fine.
    return sodium_init() >= 0;
}

}  // namespace pm
