#include "crypto.h"

#include <sodium.h>

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>

namespace pm {

static_assert(kKeyBytes == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(kSaltBytes == crypto_pwhash_SALTBYTES);

bool init_crypto() {
    // sodium_init returns 1 if it was already initialized, which is fine.
    return sodium_init() >= 0;
}

SecureBuffer::SecureBuffer(std::size_t size) : size_(size) {
    // Ask for at least one byte so an empty buffer still has a valid pointer.
    data_ = static_cast<unsigned char*>(sodium_malloc(std::max<std::size_t>(size, 1)));
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
}

SecureBuffer::~SecureBuffer() {
    sodium_free(data_);  // zeroes the memory; accepts nullptr
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        sodium_free(data_);
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

void wipe(std::string& s) {
    sodium_memzero(s.data(), s.size());
}

KdfParams KdfParams::defaults() {
    return {crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE};
}

KdfParams KdfParams::fastest() {
    return {crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
}

SecureBuffer derive_key(std::string_view password, const unsigned char* salt,
                        const KdfParams& params) {
    SecureBuffer key(kKeyBytes);
    if (crypto_pwhash(key.data(), key.size(), password.data(), password.size(), salt,
                      params.opslimit, static_cast<std::size_t>(params.memlimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("key derivation failed (out of memory?)");
    }
    return key;
}

}  // namespace pm
