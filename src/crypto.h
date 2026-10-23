#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace pm {

// Initializes libsodium. Must be called once before any other crypto call.
// Returns false if the library could not be initialized.
bool init_crypto();

// Memory for secrets, from sodium_malloc: locked so it is not swapped to
// disk, surrounded by guard pages, and zeroed when freed.
class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t size);
    ~SecureBuffer();

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    unsigned char* data() { return data_; }
    const unsigned char* data() const { return data_; }
    std::size_t size() const { return size_; }

private:
    unsigned char* data_ = nullptr;
    std::size_t size_ = 0;
};

// Overwrites a string's characters with zeros.
void wipe(std::string& s);

// Argon2id cost settings, stored in the vault file so they can be raised
// later without breaking old vaults.
struct KdfParams {
    std::uint64_t opslimit = 0;  // passes over memory
    std::uint64_t memlimit = 0;  // bytes

    // libsodium's "moderate" settings: 3 passes, 256 MiB.
    static KdfParams defaults();
    // libsodium's minimum settings. Only for tests: far too weak for real use.
    static KdfParams fastest();

    bool operator==(const KdfParams&) const = default;
};

inline constexpr std::size_t kKeyBytes = 32;
inline constexpr std::size_t kSaltBytes = 16;

// Derives a kKeyBytes key from the password with Argon2id. salt must point
// to kSaltBytes bytes. Throws std::runtime_error if Argon2id fails, which
// happens when the memory cannot be allocated.
SecureBuffer derive_key(std::string_view password, const unsigned char* salt,
                        const KdfParams& params);

}  // namespace pm
