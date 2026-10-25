#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "crypto.h"
#include "file_io.h"
#include "temp_dir.h"
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
    TempDir dir;
    pm::save_vault(dir / "v.pmv", vault, kPassword, pm::KdfParams::fastest());
    EXPECT_EQ(pm::load_vault(dir / "v.pmv", kPassword).entries(), vault.entries());
}

TEST_F(VaultFileTest, LoadMissingFileThrows) {
    TempDir dir;
    EXPECT_THROW(pm::load_vault(dir / "missing.pmv", kPassword), std::runtime_error);
}

TEST_F(VaultFileTest, BackupPathAddsBakSuffix) {
    EXPECT_EQ(pm::backup_path("dir/vault.pmv"), std::filesystem::path("dir/vault.pmv.bak"));
}

TEST_F(VaultFileTest, FirstSaveMakesNoBackup) {
    TempDir dir;
    pm::save_vault(dir / "v.pmv", vault, kPassword, pm::KdfParams::fastest());
    EXPECT_FALSE(std::filesystem::exists(dir / "v.pmv.bak"));
}

TEST_F(VaultFileTest, EachSaveBacksUpThePreviousVersion) {
    TempDir dir;
    auto path = dir / "v.pmv";
    auto fast = pm::KdfParams::fastest();

    pm::save_vault(path, vault, kPassword, fast);
    auto first = pm::read_file(path);

    pm::Entry e;
    e.title = "Second";
    vault.add(e);
    pm::save_vault(path, vault, kPassword, fast);
    EXPECT_EQ(pm::read_file(dir / "v.pmv.bak"), first);
    EXPECT_EQ(pm::load_vault(dir / "v.pmv.bak", kPassword).size(), 1u);
    EXPECT_EQ(pm::load_vault(path, kPassword).size(), 2u);

    auto second = pm::read_file(path);
    pm::save_vault(path, vault, kPassword, fast);
    EXPECT_EQ(pm::read_file(dir / "v.pmv.bak"), second);
}

TEST_F(VaultFileTest, FailedEncryptLeavesFilesUntouched) {
    TempDir dir;
    auto path = dir / "v.pmv";
    pm::save_vault(path, vault, kPassword, pm::KdfParams::fastest());
    auto before = pm::read_file(path);

    EXPECT_THROW(pm::save_vault(path, vault, kPassword, pm::KdfParams{0, 0}),
                 std::invalid_argument);
    EXPECT_EQ(pm::read_file(path), before);
    EXPECT_FALSE(std::filesystem::exists(dir / "v.pmv.bak"));
}

TEST_F(VaultFileTest, DefaultParamsRoundTrip) {
    // The real settings (256 MiB); slower, so only one test uses them.
    auto bytes = pm::encrypt_vault(vault, kPassword);
    EXPECT_EQ(pm::decrypt_vault(bytes, kPassword).entries(), vault.entries());
}

}  // namespace
