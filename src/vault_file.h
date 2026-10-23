#pragma once

#include <filesystem>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "crypto.h"
#include "vault.h"
#include "vault_json.h"

namespace pm {

// Thrown when decryption fails. The cause is deliberately not reported:
// a wrong password and a tampered or corrupted file look the same.
class DecryptError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Version of the encrypted file layout:
//
//   magic "PMVT"      4 bytes
//   version           2 bytes, little-endian
//   opslimit          8 bytes, little-endian
//   memlimit          8 bytes, little-endian
//   salt             16 bytes
//   nonce            24 bytes
//   ciphertext + tag  rest (XChaCha20-Poly1305, the header above is
//                     authenticated as associated data)
inline constexpr int kVaultFileVersion = 1;

// Encrypts the vault with a key derived from the password. A new salt and
// nonce are generated on every call.
std::vector<unsigned char> encrypt_vault(const Vault& vault, std::string_view password,
                                         const KdfParams& params = KdfParams::defaults());

// Decrypts bytes written by encrypt_vault. Throws FormatError if the bytes
// are not a vault file this version understands, DecryptError if the
// password is wrong or the file was changed.
Vault decrypt_vault(std::span<const unsigned char> data, std::string_view password,
                    Clock clock = system_now);

// encrypt_vault/decrypt_vault plus file I/O. I/O failures throw
// std::runtime_error.
void save_vault(const std::filesystem::path& path, const Vault& vault,
                std::string_view password, const KdfParams& params = KdfParams::defaults());
Vault load_vault(const std::filesystem::path& path, std::string_view password,
                 Clock clock = system_now);

}  // namespace pm
