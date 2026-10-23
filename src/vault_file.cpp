#include "vault_file.h"

#include <sodium.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>

namespace pm {

namespace {

constexpr unsigned char kMagic[4] = {'P', 'M', 'V', 'T'};
constexpr std::size_t kNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kTagBytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;

constexpr std::size_t kVersionOffset = sizeof kMagic;
constexpr std::size_t kOpsOffset = kVersionOffset + 2;
constexpr std::size_t kMemOffset = kOpsOffset + 8;
constexpr std::size_t kSaltOffset = kMemOffset + 8;
constexpr std::size_t kNonceOffset = kSaltOffset + kSaltBytes;
constexpr std::size_t kHeaderBytes = kNonceOffset + kNonceBytes;

// Upper limits on the cost settings read from a file, so a crafted file
// cannot make us run for hours or allocate all memory.
constexpr std::uint64_t kMaxOpslimit = 32;
constexpr std::uint64_t kMaxMemlimit = std::uint64_t{1} << 30;  // 1 GiB

void put_le(std::vector<unsigned char>& out, std::uint64_t value, int bytes) {
    for (int i = 0; i < bytes; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

std::uint64_t get_le(const unsigned char* p, int bytes) {
    std::uint64_t value = 0;
    for (int i = 0; i < bytes; ++i) {
        value |= std::uint64_t{p[i]} << (8 * i);
    }
    return value;
}

bool params_in_range(const KdfParams& p) {
    return p.opslimit >= crypto_pwhash_OPSLIMIT_MIN && p.opslimit <= kMaxOpslimit &&
           p.memlimit >= crypto_pwhash_MEMLIMIT_MIN && p.memlimit <= kMaxMemlimit;
}

}  // namespace

std::vector<unsigned char> encrypt_vault(const Vault& vault, std::string_view password,
                                         const KdfParams& params) {
    if (!params_in_range(params)) {
        throw std::invalid_argument("key derivation settings out of range");
    }

    unsigned char salt[kSaltBytes];
    unsigned char nonce[kNonceBytes];
    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> out(std::begin(kMagic), std::end(kMagic));
    put_le(out, kVaultFileVersion, 2);
    put_le(out, params.opslimit, 8);
    put_le(out, params.memlimit, 8);
    out.insert(out.end(), std::begin(salt), std::end(salt));
    out.insert(out.end(), std::begin(nonce), std::end(nonce));

    SecureBuffer key = derive_key(password, salt, params);
    std::string json = to_json(vault);

    out.resize(kHeaderBytes + json.size() + kTagBytes);
    unsigned long long cipher_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + kHeaderBytes, &cipher_len,
        reinterpret_cast<const unsigned char*>(json.data()), json.size(),
        out.data(), kHeaderBytes,  // header as associated data
        nullptr, nonce, key.data());
    wipe(json);
    return out;
}

Vault decrypt_vault(std::span<const unsigned char> data, std::string_view password,
                    Clock clock) {
    if (data.size() < kHeaderBytes + kTagBytes) {
        throw FormatError("file is too short to be a vault");
    }
    if (std::memcmp(data.data(), kMagic, sizeof kMagic) != 0) {
        throw FormatError("not a passwordManager vault file");
    }
    std::uint64_t version = get_le(data.data() + kVersionOffset, 2);
    if (version != kVaultFileVersion) {
        throw FormatError("unsupported vault file version " + std::to_string(version));
    }
    KdfParams params{get_le(data.data() + kOpsOffset, 8), get_le(data.data() + kMemOffset, 8)};
    if (!params_in_range(params)) {
        throw FormatError("vault file has unsupported key derivation settings");
    }

    SecureBuffer key = derive_key(password, data.data() + kSaltOffset, params);

    std::span<const unsigned char> cipher = data.subspan(kHeaderBytes);
    SecureBuffer plain(cipher.size() - kTagBytes);
    unsigned long long plain_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain.data(), &plain_len, nullptr,
            cipher.data(), cipher.size(),
            data.data(), kHeaderBytes,
            data.data() + kNonceOffset, key.data()) != 0) {
        throw DecryptError("wrong master password or corrupted vault file");
    }

    std::string_view json(reinterpret_cast<const char*>(plain.data()), plain_len);
    return from_json(json, std::move(clock));
}

void save_vault(const std::filesystem::path& path, const Vault& vault,
                std::string_view password, const KdfParams& params) {
    std::vector<unsigned char> bytes = encrypt_vault(vault, password, params);
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    file.close();
    if (!file) {
        throw std::runtime_error("cannot write vault file " + path.string());
    }
}

Vault load_vault(const std::filesystem::path& path, std::string_view password, Clock clock) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot open vault file " + path.string());
    }
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    if (file.bad()) {
        throw std::runtime_error("cannot read vault file " + path.string());
    }
    return decrypt_vault(bytes, password, std::move(clock));
}

}  // namespace pm
