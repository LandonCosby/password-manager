#include <gtest/gtest.h>

#include <stdexcept>

#include "crypto.h"
#include "vault.h"

namespace {

// A clock the test can move forward by hand.
struct FakeClock {
    std::int64_t now = 1000;
};

class VaultTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(pm::init_crypto()); }

    pm::Entry make(std::string title, std::string username = "", std::string url = "") {
        pm::Entry e;
        e.title = std::move(title);
        e.username = std::move(username);
        e.url = std::move(url);
        e.password = "hunter2";
        return e;
    }

    FakeClock clock;
    pm::Vault vault{[this] { return clock.now; }};
};

TEST_F(VaultTest, StartsEmpty) {
    EXPECT_EQ(vault.size(), 0u);
    EXPECT_TRUE(vault.entries().empty());
}

TEST_F(VaultTest, AddAssignsIdAndTimestamps) {
    pm::Entry e = make("GitHub");
    e.id = "caller-chosen";
    e.created = e.modified = 5;

    std::string id = vault.add(e);

    const pm::Entry* stored = vault.find(id);
    ASSERT_NE(stored, nullptr);
    EXPECT_NE(stored->id, "caller-chosen");
    EXPECT_EQ(stored->id.size(), 32u);
    EXPECT_EQ(stored->title, "GitHub");
    EXPECT_EQ(stored->password, "hunter2");
    EXPECT_EQ(stored->created, 1000);
    EXPECT_EQ(stored->modified, 1000);
}

TEST_F(VaultTest, IdsAreUnique) {
    std::string a = vault.add(make("A"));
    std::string b = vault.add(make("B"));
    EXPECT_NE(a, b);
}

TEST_F(VaultTest, FindUnknownIdReturnsNull) {
    vault.add(make("A"));
    EXPECT_EQ(vault.find("nope"), nullptr);
}

TEST_F(VaultTest, UpdateKeepsCreatedAndBumpsModified) {
    std::string id = vault.add(make("Old title"));
    clock.now = 2000;

    pm::Entry changed = *vault.find(id);
    changed.title = "New title";
    changed.created = 1;  // must be ignored
    ASSERT_TRUE(vault.update(changed));

    const pm::Entry* stored = vault.find(id);
    EXPECT_EQ(stored->title, "New title");
    EXPECT_EQ(stored->created, 1000);
    EXPECT_EQ(stored->modified, 2000);
}

TEST_F(VaultTest, UpdateUnknownIdFails) {
    pm::Entry e = make("Ghost");
    e.id = "missing";
    EXPECT_FALSE(vault.update(e));
    EXPECT_EQ(vault.size(), 0u);
}

TEST_F(VaultTest, RemoveDeletesOnlyThatEntry) {
    std::string a = vault.add(make("A"));
    std::string b = vault.add(make("B"));

    EXPECT_TRUE(vault.remove(a));
    EXPECT_EQ(vault.find(a), nullptr);
    EXPECT_NE(vault.find(b), nullptr);
    EXPECT_FALSE(vault.remove(a));
}

TEST_F(VaultTest, SearchMatchesTitleUsernameAndUrlIgnoringCase) {
    vault.add(make("GitHub", "landon", "https://github.com"));
    vault.add(make("Email", "me@example.com", "https://mail.example.com"));
    vault.add(make("Bank", "acct42", "https://bank.test"));

    EXPECT_EQ(vault.search("github").size(), 1u);
    EXPECT_EQ(vault.search("EXAMPLE").size(), 1u);
    EXPECT_EQ(vault.search("acct").size(), 1u);
    EXPECT_EQ(vault.search("https").size(), 3u);
    EXPECT_EQ(vault.search("nothing").size(), 0u);
    EXPECT_EQ(vault.search("").size(), 3u);
}

TEST_F(VaultTest, SearchDoesNotLookAtPasswordsOrNotes) {
    pm::Entry e = make("Site");
    e.password = "secretword";
    e.notes = "secretword";
    vault.add(e);
    EXPECT_TRUE(vault.search("secretword").empty());
}

TEST(VaultLoad, RejectsDuplicateIds) {
    pm::Entry e;
    e.id = "same";
    EXPECT_THROW(pm::Vault({e, e}), std::invalid_argument);
}

TEST(VaultLoad, RejectsEmptyId) {
    EXPECT_THROW(pm::Vault({pm::Entry{}}), std::invalid_argument);
}

}  // namespace
