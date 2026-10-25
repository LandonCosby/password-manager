#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto.h"
#include "file_io.h"
#include "temp_dir.h"

namespace {

namespace fs = std::filesystem;

std::vector<unsigned char> bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

// Sets an environment variable for the lifetime of the object, then
// restores the old value.
class ScopedEnv {
public:
    ScopedEnv(const char* name, const char* value) : name_(name) {
        if (const char* old = std::getenv(name)) {
            old_ = old;
        }
        set(value);
    }
    ~ScopedEnv() { set(old_ ? old_->c_str() : nullptr); }

private:
    void set(const char* value) {
#ifdef _WIN32
        _putenv_s(name_.c_str(), value ? value : "");  // "" removes it
#else
        if (value) {
            setenv(name_.c_str(), value, 1);
        } else {
            unsetenv(name_.c_str());
        }
#endif
    }

    std::string name_;
    std::optional<std::string> old_;
};

class FileIoTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(pm::init_crypto()); }
};

TEST_F(FileIoTest, WriteThenReadReturnsSameBytes) {
    TempDir dir;
    auto data = bytes(std::string("binary\0data\xff", 12));
    pm::write_file_atomic(dir / "f", data);
    EXPECT_EQ(pm::read_file(dir / "f"), data);
}

TEST_F(FileIoTest, EmptyDataWritesEmptyFile) {
    TempDir dir;
    pm::write_file_atomic(dir / "f", {});
    EXPECT_TRUE(pm::read_file(dir / "f").empty());
}

TEST_F(FileIoTest, OverwriteReplacesContents) {
    TempDir dir;
    pm::write_file_atomic(dir / "f", bytes("a much longer first version"));
    pm::write_file_atomic(dir / "f", bytes("short"));
    EXPECT_EQ(pm::read_file(dir / "f"), bytes("short"));
}

TEST_F(FileIoTest, NoTempFileIsLeftBehind) {
    TempDir dir;
    pm::write_file_atomic(dir / "f", bytes("x"));
    pm::write_file_atomic(dir / "f", bytes("y"));
    EXPECT_FALSE(fs::exists(dir / "f.tmp"));
    EXPECT_EQ(std::distance(fs::directory_iterator(dir.path()), fs::directory_iterator()), 1);
}

TEST_F(FileIoTest, StaleTempFileFromACrashIsOverwritten) {
    TempDir dir;
    pm::write_file_atomic(dir / "f.tmp", bytes("left over from a crash"));
    pm::write_file_atomic(dir / "f", bytes("new"));
    EXPECT_EQ(pm::read_file(dir / "f"), bytes("new"));
    EXPECT_FALSE(fs::exists(dir / "f.tmp"));
}

TEST_F(FileIoTest, MissingFolderThrowsAndCreatesNothing) {
    TempDir dir;
    EXPECT_THROW(pm::write_file_atomic(dir / "no_such_dir" / "f", bytes("x")), std::runtime_error);
    EXPECT_FALSE(fs::exists(dir / "no_such_dir"));
}

TEST_F(FileIoTest, FailedReplaceLeavesTargetAndRemovesTemp) {
    TempDir dir;
    // A folder cannot be replaced by a file, so the rename step fails.
    fs::create_directory(dir / "f");
    EXPECT_THROW(pm::write_file_atomic(dir / "f", bytes("x")), std::runtime_error);
    EXPECT_TRUE(fs::is_directory(dir / "f"));
    EXPECT_FALSE(fs::exists(dir / "f.tmp"));
}

TEST_F(FileIoTest, ReadMissingFileThrows) {
    TempDir dir;
    EXPECT_THROW(pm::read_file(dir / "missing"), std::runtime_error);
}

TEST_F(FileIoTest, DefaultVaultPathHonoursOverride) {
    ScopedEnv env("PASSWORDMANAGER_VAULT", "C:/somewhere/my.pmv");
    EXPECT_EQ(pm::default_vault_path(), fs::path("C:/somewhere/my.pmv"));
}

#ifdef _WIN32
TEST_F(FileIoTest, DefaultVaultPathIsUnderAppData) {
    ScopedEnv no_override("PASSWORDMANAGER_VAULT", nullptr);
    ScopedEnv appdata("APPDATA", "C:\\Users\\test\\AppData\\Roaming");
    EXPECT_EQ(pm::default_vault_path(),
              fs::path("C:\\Users\\test\\AppData\\Roaming") / "passwordManager" / "vault.pmv");
}

TEST_F(FileIoTest, DefaultVaultPathWithoutAppDataThrows) {
    ScopedEnv no_override("PASSWORDMANAGER_VAULT", nullptr);
    ScopedEnv no_appdata("APPDATA", nullptr);
    EXPECT_THROW(pm::default_vault_path(), std::runtime_error);
}
#endif

}  // namespace
