#include <gtest/gtest.h>

#include "crypto.h"
#include "vault_json.h"

namespace {

class VaultJsonTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(pm::init_crypto()); }
};

TEST_F(VaultJsonTest, EmptyVaultRoundTrips) {
    pm::Vault loaded = pm::from_json(pm::to_json(pm::Vault{}));
    EXPECT_EQ(loaded.size(), 0u);
}

TEST_F(VaultJsonTest, EntriesRoundTripExactly) {
    pm::Vault vault{[] { return std::int64_t{1700000000}; }};

    pm::Entry a;
    a.title = "GitHub";
    a.username = "landon";
    a.password = "p@ss \"quoted\" \\ back\nslash";
    a.url = "https://github.com";
    a.notes = "line one\nline two \xC3\xA9";  // UTF-8 "é"
    vault.add(a);

    pm::Entry b;
    b.title = "Empty fields";
    vault.add(b);

    pm::Vault loaded = pm::from_json(pm::to_json(vault));
    EXPECT_EQ(loaded.entries(), vault.entries());
}

TEST_F(VaultJsonTest, OutputHasVersion) {
    std::string text = pm::to_json(pm::Vault{});
    EXPECT_NE(text.find("\"version\":1"), std::string::npos);
}

TEST_F(VaultJsonTest, RejectsNonJson) {
    EXPECT_THROW(pm::from_json("not json"), pm::FormatError);
    EXPECT_THROW(pm::from_json(""), pm::FormatError);
}

TEST_F(VaultJsonTest, RejectsWrongVersion) {
    EXPECT_THROW(pm::from_json(R"({"version":2,"entries":[]})"), pm::FormatError);
}

TEST_F(VaultJsonTest, RejectsMissingFields) {
    EXPECT_THROW(pm::from_json(R"({"entries":[]})"), pm::FormatError);
    EXPECT_THROW(pm::from_json(R"({"version":1})"), pm::FormatError);
    EXPECT_THROW(pm::from_json(R"({"version":1,"entries":[{"id":"x"}]})"), pm::FormatError);
}

TEST_F(VaultJsonTest, RejectsWrongTypes) {
    EXPECT_THROW(pm::from_json(R"({"version":"1","entries":[]})"), pm::FormatError);
    EXPECT_THROW(pm::from_json(R"({"version":1,"entries":{}})"), pm::FormatError);
}

TEST_F(VaultJsonTest, RejectsDuplicateIds) {
    const char* text = R"({"version":1,"entries":[
        {"id":"a","title":"","username":"","password":"","url":"","notes":"","created":0,"modified":0},
        {"id":"a","title":"","username":"","password":"","url":"","notes":"","created":0,"modified":0}
    ]})";
    EXPECT_THROW(pm::from_json(text), pm::FormatError);
}

}  // namespace
