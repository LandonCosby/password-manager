#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

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

// A string that is wiped when destroyed. Moving copies the characters and
// wipes the source, so no stale copy is left in the moved-from object.
class SecretString {
public:
    SecretString() = default;
    explicit SecretString(std::string value) : value_(std::move(value)) {}
    ~SecretString() { wipe(value_); }

    SecretString(SecretString&& other) noexcept : value_(other.value_) { other.clear(); }
    SecretString& operator=(SecretString&& other) noexcept {
        if (this != &other) {
            wipe(value_);
            value_ = other.value_;
            other.clear();
        }
        return *this;
    }
    SecretString(const SecretString&) = delete;
    SecretString& operator=(const SecretString&) = delete;

    const std::string& str() const { return value_; }
    std::string_view view() const { return value_; }
    std::size_t size() const { return value_.size(); }
    bool empty() const { return value_.empty(); }

private:
    void clear() {
        wipe(value_);
        value_.clear();
    }

    std::string value_;
};

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
