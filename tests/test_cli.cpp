#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "cli.h"
#include "crypto.h"
#include "fake_terminal.h"
#include "file_io.h"
#include "temp_dir.h"
#include "vault_file.h"

namespace {

namespace fs = std::filesystem;

constexpr const char* kMaster = "Password1234";

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

class CliTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(pm::init_crypto());
        path = dir / "v.pmv";
    }

    // Runs one command against the test vault with the given answers to
    // prompts, in order.
    FakeTerminal run(std::vector<std::string> args, std::vector<std::string> input = {}) {
        args.insert(args.begin(), {"--vault", path.string()});
        FakeTerminal t(std::move(input));
        code = pm::run_cli(args, t, pm::KdfParams::fastest());
        return t;
    }

    void init() {
        run({"init"}, {kMaster, kMaster});
        ASSERT_EQ(code, 0);
    }

    // Adds an entry with every field given on the command line.
    void add(const std::string& title, const std::string& user, const std::string& password,
             const std::string& url = "") {
        run({"add", title, "-u", user, "--url", url, "--notes", ""}, {kMaster, password, password});
        ASSERT_EQ(code, 0);
    }

    pm::Vault load() { return pm::load_vault(path, kMaster); }

    TempDir dir;
    fs::path path;
    int code = -1;
};

// --- init -----------------------------------------------------------------

TEST_F(CliTest, InitCreatesEmptyVault) {
    FakeTerminal t = run({"init"}, {kMaster, kMaster});
    EXPECT_EQ(code, 0);
    EXPECT_TRUE(contains(t.output(), "Created vault"));
    EXPECT_EQ(load().size(), 0u);
    EXPECT_EQ(t.secret_prompts.size(), 2u);
}

TEST_F(CliTest, InitCreatesMissingFolders) {
    path = dir / "a" / "b" / "v.pmv";
    init();
    EXPECT_TRUE(fs::exists(path));
}

TEST_F(CliTest, InitRejectsMismatchedPasswords) {
    FakeTerminal t = run({"init"}, {kMaster, "Password12345"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "do not match"));
    EXPECT_FALSE(fs::exists(path));
}

TEST_F(CliTest, InitRejectsShortPassword) {
    FakeTerminal t = run({"init"}, {"short"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "at least 8"));
    EXPECT_FALSE(fs::exists(path));
}

TEST_F(CliTest, InitRefusesToOverwrite) {
    init();
    auto before = pm::read_file(path);
    FakeTerminal t = run({"init"}, {"OtherPassword", "OtherPassword"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "already exists"));
    EXPECT_EQ(pm::read_file(path), before);
}

// --- unlocking ------------------------------------------------------------

TEST_F(CliTest, CommandsWithoutVaultSuggestInit) {
    FakeTerminal t = run({"list"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "init"));
    EXPECT_TRUE(t.prompts.empty());  // no point asking for a password
}

TEST_F(CliTest, WrongMasterPasswordIsReported) {
    init();
    FakeTerminal t = run({"list"}, {"WrongPassword"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "wrong master password"));
}

TEST_F(CliTest, MasterPasswordIsAskedForHidden) {
    init();
    FakeTerminal t = run({"list"}, {kMaster});
    ASSERT_EQ(t.secret_prompts.size(), 1u);
    EXPECT_EQ(t.secret_prompts[0], "Master password: ");
}

// --- add ------------------------------------------------------------------

TEST_F(CliTest, AddPromptsForMissingFields) {
    init();
    FakeTerminal t = run({"add", "GitHub"},
                         {kMaster, "landon", "s3cret!", "s3cret!", "https://github.com", "work"});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Added 'GitHub'"));
    EXPECT_EQ(t.unused_input(), 0u);

    pm::Vault v = load();
    ASSERT_EQ(v.size(), 1u);
    const pm::Entry& e = v.entries()[0];
    EXPECT_EQ(e.title, "GitHub");
    EXPECT_EQ(e.username, "landon");
    EXPECT_EQ(e.password, "s3cret!");
    EXPECT_EQ(e.url, "https://github.com");
    EXPECT_EQ(e.notes, "work");
}

TEST_F(CliTest, AddWithFlagsOnlyAsksForPasswords) {
    init();
    FakeTerminal t = run({"add", "GitHub", "-u", "landon", "--url", "u", "--notes", "n"},
                         {kMaster, "pw", "pw"});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_EQ(t.prompts.size(), 3u);
    EXPECT_EQ(t.secret_prompts.size(), 3u);
}

TEST_F(CliTest, AddRejectsMismatchedPasswordAndSavesNothing) {
    init();
    FakeTerminal t = run({"add", "GitHub", "-u", "x"}, {kMaster, "one", "two"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "do not match"));
    EXPECT_EQ(load().size(), 0u);
}

TEST_F(CliTest, AddRejectsEmptyPassword) {
    init();
    FakeTerminal t = run({"add", "GitHub", "-u", "x"}, {kMaster, ""});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "must not be empty"));
}

TEST_F(CliTest, AddRequiresTitle) {
    init();
    FakeTerminal t = run({"add"});
    EXPECT_NE(code, 0);
    EXPECT_FALSE(t.errors().empty());
}

TEST_F(CliTest, NonAsciiTextRoundTrips) {
    init();
    add("Caf\xC3\xA9", "j\xC3\xBCrgen", "p\xC3\xA4ss");  // Café, jürgen, päss
    FakeTerminal t = run({"get", "caf\xC3\xA9", "--show"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Password: p\xC3\xA4ss"));
}

// --- get ------------------------------------------------------------------

TEST_F(CliTest, GetCopiesPasswordAndClearsIt) {
    init();
    add("GitHub", "landon", "s3cret!");
    FakeTerminal t = run({"get", "GitHub"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Username: landon"));
    EXPECT_TRUE(contains(t.output(), "copied to the clipboard"));
    EXPECT_TRUE(contains(t.output(), "Clipboard cleared"));
    EXPECT_FALSE(contains(t.output(), "s3cret!"));
    EXPECT_EQ(t.waited_seconds, 30);
    EXPECT_TRUE(t.clipboard.empty());
}

TEST_F(CliTest, GetShowPrintsPasswordWithoutClipboard) {
    init();
    add("GitHub", "landon", "s3cret!");
    FakeTerminal t = run({"get", "GitHub", "--show"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Password: s3cret!"));
    EXPECT_EQ(t.waited_seconds, -1);
}

TEST_F(CliTest, GetWithoutClipboardSuggestsShow) {
    init();
    add("GitHub", "landon", "s3cret!");
    FakeTerminal t({kMaster});
    t.clipboard_supported = false;
    code = pm::run_cli({"--vault", path.string(), "get", "GitHub"}, t, pm::KdfParams::fastest());
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "--show"));
}

TEST_F(CliTest, GetUnknownEntryFails) {
    init();
    FakeTerminal t = run({"get", "nothing"}, {kMaster});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "no entry matches 'nothing'"));
}

TEST_F(CliTest, ExactTitleBeatsSearch) {
    init();
    add("GitHub", "personal", "a");
    add("GitHub Enterprise", "work", "b");
    FakeTerminal t = run({"get", "github", "--show"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Username: personal"));
}

TEST_F(CliTest, AmbiguousQueryListsMatches) {
    init();
    add("GitHub", "personal", "a");
    add("GitLab", "work", "b");
    FakeTerminal t = run({"get", "git"}, {kMaster});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "matches 2 entries"));
    EXPECT_TRUE(contains(t.errors(), "GitHub"));
    EXPECT_TRUE(contains(t.errors(), "GitLab"));
}

TEST_F(CliTest, IdPrefixSelectsEntry) {
    init();
    add("Same", "first", "a");
    add("Same", "second", "b");
    std::string id;
    pm::Vault v = load();
    for (const pm::Entry& e : v.entries()) {
        if (e.username == "second") id = e.id;
    }
    FakeTerminal t = run({"get", id.substr(0, 8), "--show"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "Username: second"));
}

// --- list and search --------------------------------------------------------

TEST_F(CliTest, ListEmptyVault) {
    init();
    FakeTerminal t = run({"list"}, {kMaster});
    EXPECT_EQ(code, 0);
    EXPECT_TRUE(contains(t.output(), "No entries"));
}

TEST_F(CliTest, ListShowsEntriesSortedWithoutPasswords) {
    init();
    add("zeta", "z", "pw-zeta");
    add("Alpha", "a", "pw-alpha", "https://alpha.test");
    FakeTerminal t = run({"list"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    std::string out = t.output();
    EXPECT_TRUE(contains(out, "TITLE"));
    EXPECT_TRUE(contains(out, "https://alpha.test"));
    EXPECT_LT(out.find("Alpha"), out.find("zeta"));
    EXPECT_FALSE(contains(out, "pw-"));
}

TEST_F(CliTest, SearchListsMatchesOnly) {
    init();
    add("GitHub", "landon", "a");
    add("Bank", "acct", "b");
    FakeTerminal t = run({"search", "LANDON"}, {kMaster});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_TRUE(contains(t.output(), "GitHub"));
    EXPECT_FALSE(contains(t.output(), "Bank"));

    FakeTerminal none = run({"search", "zzz"}, {kMaster});
    EXPECT_TRUE(contains(none.output(), "No entries match"));
}

// --- edit -----------------------------------------------------------------

TEST_F(CliTest, EditKeepsChangesAndClearsFields) {
    init();
    add("GitHub", "landon", "old-pw", "https://github.com");
    // Title: keep; username: change; URL: clear; notes: set; password: keep.
    FakeTerminal t = run({"edit", "GitHub"}, {kMaster, "", "landon2", "-", "new notes", "n"});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_EQ(t.unused_input(), 0u);

    pm::Vault v = load();
    const pm::Entry& e = v.entries()[0];
    EXPECT_EQ(e.title, "GitHub");
    EXPECT_EQ(e.username, "landon2");
    EXPECT_EQ(e.url, "");
    EXPECT_EQ(e.notes, "new notes");
    EXPECT_EQ(e.password, "old-pw");
}

TEST_F(CliTest, EditShowsCurrentValuesInPrompts) {
    init();
    add("GitHub", "landon", "pw");
    FakeTerminal t = run({"edit", "GitHub"}, {kMaster, "", "", "", "", ""});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_EQ(t.prompts[1], "Title [GitHub]: ");
    EXPECT_EQ(t.prompts[2], "Username [landon]: ");
    EXPECT_EQ(t.prompts[3], "URL: ");
}

TEST_F(CliTest, EditCanChangePassword) {
    init();
    add("GitHub", "landon", "old-pw");
    FakeTerminal t = run({"edit", "GitHub"}, {kMaster, "", "", "", "", "y", "new-pw", "new-pw"});
    ASSERT_EQ(code, 0) << t.errors();
    EXPECT_EQ(load().entries()[0].password, "new-pw");
}

TEST_F(CliTest, EditRejectsEmptyTitle) {
    init();
    add("GitHub", "landon", "pw");
    FakeTerminal t = run({"edit", "GitHub"}, {kMaster, "-"});
    EXPECT_EQ(code, 1);
    EXPECT_TRUE(contains(t.errors(), "title cannot be empty"));
    EXPECT_EQ(load().entries()[0].title, "GitHub");
}

// --- delete ---------------------------------------------------------------

TEST_F(CliTest, DeleteAsksForConfirmation) {
    init();
    add("GitHub", "landon", "pw");

    FakeTerminal no = run({"delete", "GitHub"}, {kMaster, "n"});
    EXPECT_EQ(code, 0);
    EXPECT_TRUE(contains(no.output(), "Not deleted"));
    EXPECT_EQ(load().size(), 1u);

    FakeTerminal yes = run({"delete", "GitHub"}, {kMaster, "y"});
    EXPECT_EQ(code, 0);
    EXPECT_TRUE(contains(yes.output(), "Deleted 'GitHub'"));
    EXPECT_EQ(load().size(), 0u);
}

TEST_F(CliTest, DeleteYesSkipsConfirmation) {
    init();
    add("GitHub", "landon", "pw");
    FakeTerminal t = run({"delete", "GitHub", "--yes"}, {kMaster});
    EXPECT_EQ(code, 0);
    EXPECT_EQ(t.prompts.size(), 1u);
    EXPECT_EQ(load().size(), 0u);
}

// --- change-master ----------------------------------------------------------

TEST_F(CliTest, ChangeMasterReencryptsVaultAndBackup) {
    init();
    add("GitHub", "landon", "pw");
    FakeTerminal t = run({"change-master"}, {kMaster, "NewMaster99", "NewMaster99"});
    ASSERT_EQ(code, 0) << t.errors();

    EXPECT_THROW(pm::load_vault(path, kMaster), pm::DecryptError);
    EXPECT_EQ(pm::load_vault(path, "NewMaster99").size(), 1u);

    auto bak = pm::backup_path(path);
    EXPECT_THROW(pm::load_vault(bak, kMaster), pm::DecryptError);
    EXPECT_EQ(pm::load_vault(bak, "NewMaster99").size(), 1u);
}

TEST_F(CliTest, ChangeMasterRejectsShortPassword) {
    init();
    FakeTerminal t = run({"change-master"}, {kMaster, "short"});
    EXPECT_EQ(code, 1);
    EXPECT_NO_THROW(pm::load_vault(path, kMaster));
}

// --- parsing --------------------------------------------------------------

TEST_F(CliTest, NoCommandIsAnError) {
    FakeTerminal t = run({});
    EXPECT_NE(code, 0);
    EXPECT_FALSE(t.errors().empty());
}

TEST_F(CliTest, UnknownCommandIsAnError) {
    FakeTerminal t = run({"frobnicate"});
    EXPECT_NE(code, 0);
}

TEST_F(CliTest, HelpListsCommands) {
    FakeTerminal t = run({"--help"});
    EXPECT_EQ(code, 0);
    for (const char* cmd : {"init", "add", "get", "list", "search", "edit", "delete", "change-master"}) {
        EXPECT_TRUE(contains(t.output(), cmd)) << cmd;
    }
}

TEST_F(CliTest, VersionFlag) {
    FakeTerminal t = run({"--version"});
    EXPECT_EQ(code, 0);
    EXPECT_TRUE(contains(t.output(), "0.2.0"));
}

// --- SecretString -----------------------------------------------------------

TEST(SecretString, MoveLeavesSourceEmpty) {
    pm::SecretString a(std::string("secret"));
    pm::SecretString b(std::move(a));
    EXPECT_EQ(b.str(), "secret");
    EXPECT_TRUE(a.empty());

    pm::SecretString c;
    c = std::move(b);
    EXPECT_EQ(c.str(), "secret");
    EXPECT_TRUE(b.empty());
}

}  // namespace
