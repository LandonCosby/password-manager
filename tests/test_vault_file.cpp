#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "crypto.h"
#include "vault_file.h"

namespace {

constexpr const char* kPassword = "Password1234";

// Byte offsets from the layout documented in vault_file.h.
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kMemOffset = 14;
constexpr std::size_t kSaltOffset = 22;
constexpr std::size_t kHeaderBytes = 62;

class VaultFileTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pm::init_crypto());
        pm::Entry e;
        e.title = "GitHub";
        e.username = "landon";
        e.password = "correct horse battery staple";
        vault.add(e);
    }

    std::vector<unsigned char> encrypt(std::string_view password = kPassword) {
        return pm::encrypt_vault(vault, password, pm::KdfParams::fastest());
    }

    pm::Vault vault;
};

TEST_F(VaultFileTest, RoundTrip) {
    pm::Vault loaded = pm::decrypt_vault(encrypt(), kPassword);
    EXPECT_EQ(loaded.entries(), vault.entries());
}

TEST_F(VaultFileTest, EmptyVaultRoundTrips) {
    auto bytes = pm::encrypt_vault(pm::Vault{}, kPassword, pm::KdfParams::fastest());
    EXPECT_EQ(pm::decrypt_vault(bytes, kPassword).size(), 0u);
}

TEST_F(VaultFileTest, StartsWithMagicAndVersion) {
    auto bytes = encrypt();
    ASSERT_GE(bytes.size(), kHeaderBytes);
    EXPECT_EQ(std::string(bytes.begin(), bytes.begin() + 4), "PMVT");
    EXPECT_EQ(bytes[kVersionOffset], 1);
    EXPECT_EQ(bytes[kVersionOffset + 1], 0);
}

TEST_F(VaultFileTest, OutputDoesNotContainPlaintext) {
    auto bytes = encrypt();
    std::string text(bytes.begin(), bytes.end());
    EXPECT_EQ(text.find("correct horse"), std::string::npos);
    EXPECT_EQ(text.find("GitHub"), std::string::npos);
    EXPECT_EQ(text.find(kPassword), std::string::npos);
}

TEST_F(VaultFileTest, SaltAndNonceChangeEverySave) {
    auto a = encrypt();
    auto b = encrypt();
    EXPECT_FALSE(std::equal(a.begin() + kSaltOffset, a.begin() + kHeaderBytes,
                            b.begin() + kSaltOffset));
    EXPECT_NE(a, b);
}

TEST_F(VaultFileTest, WrongPasswordThrowsDecryptError) {
    auto bytes = encrypt();
    EXPECT_THROW(pm::decrypt_vault(bytes, "Password1235"), pm::DecryptError);
    EXPECT_THROW(pm::decrypt_vault(bytes, ""), pm::DecryptError);
}

TEST_F(VaultFileTest, EveryTamperedByteAfterVersionIsDetected) {
    auto original = encrypt();
    // Flip one byte at a time in the KDF settings, salt, nonce, ciphertext
    // and tag. Each change must be caught by authentication.
    for (std::size_t i = kVersionOffset + 2; i < original.size(); ++i) {
        auto bytes = original;
        bytes[i] ^= 0x01;
        // Some flips push the KDF settings out of range, which is reported
        // as a format error before any decryption is attempted.
        try {
            pm::decrypt_vault(bytes, kPassword);
            ADD_FAILURE() << "tampering at byte " << i << " was not detected";
        } catch (const pm::DecryptError&) {
        } catch (const pm::FormatError&) {
        }
    }
}

TEST_F(VaultFileTest, TruncatedFileIsRejected) {
    auto bytes = encrypt();
    bytes.resize(kHeaderBytes + 15);  // one byte short of a tag
    EXPECT_THROW(pm::decrypt_vault(bytes, kPassword), pm::FormatError);

    auto partial = encrypt();
    partial.pop_back();
    EXPECT_THROW(pm::decrypt_vault(partial, kPassword), pm::DecryptError);
}

TEST_F(VaultFileTest, WrongMagicIsRejected) {
    auto bytes = encrypt();
    bytes[0] = 'X';
    EXPECT_THROW(pm::decrypt_vault(bytes, kPassword), pm::FormatError);
}

TEST_F(VaultFileTest, UnknownVersionIsRejected) {
    auto bytes = encrypt();
    bytes[kVersionOffset] = 2;
    EXPECT_THROW(pm::decrypt_vault(bytes, kPassword), pm::FormatError);
}

TEST_F(VaultFileTest, HugeMemoryLimitIsRejectedBeforeAllocating) {
    auto bytes = encrypt();
    bytes[kMemOffset + 7] = 0x7f;  // about 9 exabytes
    EXPECT_THROW(pm::decrypt_vault(bytes, kPassword), pm::FormatError);
}

TEST_F(VaultFileTest, EncryptRejectsOutOfRangeParams) {
    EXPECT_THROW(pm::encrypt_vault(vault, kPassword, pm::KdfParams{0, 0}), std::invalid_argument);
}

TEST_F(VaultFileTest, SaveAndLoadFile) {
    auto path = std::filesystem::temp_directory_path() / "pm_test_vault.pmv";
    pm::save_vault(path, vault, kPassword, pm::KdfParams::fastest());
    pm::Vault loaded = pm::load_vault(path, kPassword);
    std::filesystem::remove(path);
    EXPECT_EQ(loaded.entries(), vault.entries());
}

TEST_F(VaultFileTest, LoadMissingFileThrows) {
    auto path = std::filesystem::temp_directory_path() / "pm_test_does_not_exist.pmv";
    std::filesystem::remove(path);
    EXPECT_THROW(pm::load_vault(path, kPassword), std::runtime_error);
}

TEST_F(VaultFileTest, DefaultParamsRoundTrip) {
    // The real settings (256 MiB); slower, so only one test uses them.
    auto bytes = pm::encrypt_vault(vault, kPassword);
    EXPECT_EQ(pm::decrypt_vault(bytes, kPassword).entries(), vault.entries());
}

}  // namespace
