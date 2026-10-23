#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <string>

#include "crypto.h"

namespace {

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(pm::init_crypto()); }

    unsigned char salt[pm::kSaltBytes] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
};

bool equal(const pm::SecureBuffer& a, const pm::SecureBuffer& b) {
    return a.size() == b.size() && std::equal(a.data(), a.data() + a.size(), b.data());
}

TEST(Crypto, InitIsSafeToCallTwice) {
    ASSERT_TRUE(pm::init_crypto());
    EXPECT_TRUE(pm::init_crypto());
}

TEST_F(CryptoTest, RandomBytesAreNotAllZero) {
    unsigned char buf[32] = {};
    randombytes_buf(buf, sizeof buf);
    EXPECT_TRUE(std::any_of(std::begin(buf), std::end(buf), [](unsigned char b) { return b != 0; }));
}

TEST_F(CryptoTest, SecureBufferHasRequestedSize) {
    pm::SecureBuffer buf(64);
    EXPECT_EQ(buf.size(), 64u);
    EXPECT_NE(buf.data(), nullptr);
}

TEST_F(CryptoTest, SecureBufferMoveTransfersOwnership) {
    pm::SecureBuffer a(16);
    unsigned char* p = a.data();
    pm::SecureBuffer b(std::move(a));
    EXPECT_EQ(b.data(), p);
    EXPECT_EQ(a.data(), nullptr);
    EXPECT_EQ(a.size(), 0u);
}

TEST_F(CryptoTest, WipeZeroesString) {
    std::string s = "secret";
    pm::wipe(s);
    EXPECT_EQ(s, std::string(6, '\0'));
}

TEST_F(CryptoTest, DeriveKeyIsDeterministic) {
    auto params = pm::KdfParams::fastest();
    EXPECT_TRUE(equal(pm::derive_key("Password1234", salt, params),
                      pm::derive_key("Password1234", salt, params)));
}

TEST_F(CryptoTest, DeriveKeyDependsOnPasswordSaltAndParams) {
    auto params = pm::KdfParams::fastest();
    pm::SecureBuffer base = pm::derive_key("Password1234", salt, params);
    EXPECT_EQ(base.size(), pm::kKeyBytes);

    EXPECT_FALSE(equal(base, pm::derive_key("Password1235", salt, params)));

    unsigned char other_salt[pm::kSaltBytes] = {};
    EXPECT_FALSE(equal(base, pm::derive_key("Password1234", other_salt, params)));

    auto stronger = params;
    stronger.opslimit += 1;
    EXPECT_FALSE(equal(base, pm::derive_key("Password1234", salt, stronger)));
}

}  // namespace
