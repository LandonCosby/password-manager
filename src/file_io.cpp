#include "file_io.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#endif

namespace pm {

namespace fs = std::filesystem;

namespace {

[[noreturn]] void fail(const std::string& what, const fs::path& path, int code) {
    throw std::runtime_error(what + " " + path.string() + ": " +
                             std::error_code(code, std::system_category()).message());
}

fs::path temp_path_for(const fs::path& path) {
    fs::path tmp = path;
    tmp += ".tmp";
    return tmp;
}

#ifdef _WIN32

void write_and_flush(const fs::path& path, std::span<const unsigned char> data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        fail("cannot create", path, static_cast<int>(GetLastError()));
    }
    std::size_t done = 0;
    while (done < data.size()) {
        DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - done, 1u << 30));
        DWORD written = 0;
        if (!WriteFile(h, data.data() + done, chunk, &written, nullptr)) {
            int code = static_cast<int>(GetLastError());
            CloseHandle(h);
            fail("cannot write", path, code);
        }
        done += written;
    }
    if (!FlushFileBuffers(h)) {
        int code = static_cast<int>(GetLastError());
        CloseHandle(h);
        fail("cannot flush", path, code);
    }
    CloseHandle(h);
}

void replace_file(const fs::path& from, const fs::path& to) {
    if (!MoveFileExW(from.c_str(), to.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fail("cannot replace", to, static_cast<int>(GetLastError()));
    }
}

#else

void write_and_flush(const fs::path& path, std::span<const unsigned char> data) {
    // 0600: only the owner can read the vault.
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fail("cannot create", path, errno);
    }
    std::size_t done = 0;
    while (done < data.size()) {
        ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            int code = errno;
            ::close(fd);
            fail("cannot write", path, code);
        }
        done += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) {
        int code = errno;
        ::close(fd);
        fail("cannot flush", path, code);
    }
    ::close(fd);
}

void replace_file(const fs::path& from, const fs::path& to) {
    if (::rename(from.c_str(), to.c_str()) != 0) {
        fail("cannot replace", to, errno);
    }
    // Flush the folder too, so the rename itself survives a power cut.
    fs::path dir = to.parent_path().empty() ? fs::path(".") : to.parent_path();
    int dfd = ::open(dir.c_str(), O_RDONLY);
    if (dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
}

#endif

}  // namespace

std::vector<unsigned char> read_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("cannot open " + path.string());
    }
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
    if (file.bad()) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return bytes;
}

void write_file_atomic(const fs::path& path, std::span<const unsigned char> data) {
    fs::path tmp = temp_path_for(path);
    try {
        write_and_flush(tmp, data);
        replace_file(tmp, path);
    } catch (...) {
        std::error_code ignored;
        fs::remove(tmp, ignored);
        throw;
    }
}

fs::path default_vault_path() {
#ifdef _WIN32
    if (const wchar_t* custom = _wgetenv(L"PASSWORDMANAGER_VAULT"); custom && *custom) {
        return custom;
    }
    if (const wchar_t* appdata = _wgetenv(L"APPDATA"); appdata && *appdata) {
        return fs::path(appdata) / "passwordManager" / "vault.pmv";
    }
    throw std::runtime_error("APPDATA is not set; set PASSWORDMANAGER_VAULT to choose a vault file");
#else
    if (const char* custom = std::getenv("PASSWORDMANAGER_VAULT"); custom && *custom) {
        return custom;
    }
    if (const char* data = std::getenv("XDG_DATA_HOME"); data && *data) {
        return fs::path(data) / "passwordManager" / "vault.pmv";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return fs::path(home) / ".local" / "share" / "passwordManager" / "vault.pmv";
    }
    throw std::runtime_error("HOME is not set; set PASSWORDMANAGER_VAULT to choose a vault file");
#endif
}

}  // namespace pm
