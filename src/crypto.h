#pragma once

namespace pm {

// Initializes libsodium. Must be called once before any other crypto call.
// Returns false if the library could not be initialized.
bool init_crypto();

}  // namespace pm
