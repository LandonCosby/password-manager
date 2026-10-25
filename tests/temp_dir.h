#pragma once

#include <sodium.h>

#include <filesystem>
#include <string>
#include <system_error>

// A fresh, empty folder under the system temp folder, deleted with
// everything in it when the object goes out of scope. Needs libsodium
// to be initialized.
class TempDir {
public:
    TempDir() {
        unsigned char bytes[8];
        randombytes_buf(bytes, sizeof bytes);
        char hex[sizeof bytes * 2 + 1];
        sodium_bin2hex(hex, sizeof hex, bytes, sizeof bytes);
        path_ = std::filesystem::temp_directory_path() / (std::string("pm_test_") + hex);
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::filesystem::path& path() const { return path_; }
    std::filesystem::path operator/(const std::string& name) const { return path_ / name; }

private:
    std::filesystem::path path_;
};
