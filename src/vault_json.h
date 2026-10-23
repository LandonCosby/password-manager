#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

#include "vault.h"

namespace pm {

// Thrown when vault JSON is malformed or has an unsupported version.
class FormatError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Version of the JSON layout written by to_json.
inline constexpr int kVaultJsonVersion = 1;

// Serializes the vault as JSON. The output holds every password in
// plaintext; it is meant to be encrypted before it touches disk.
std::string to_json(const Vault& vault);

// Parses JSON written by to_json. Throws FormatError on bad input.
Vault from_json(std::string_view text, Clock clock = system_now);

}  // namespace pm
