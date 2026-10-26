#include "terminal.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace pm {

namespace {

#ifdef _WIN32

std::string to_utf8(std::wstring_view w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n,
                        nullptr, nullptr);
    return s;
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// If Ctrl+C arrives while echo is off, put the console back the way it was
// before the default handler ends the program.
std::atomic<DWORD> g_saved_input_mode{0};
std::atomic<bool> g_echo_off{false};

BOOL WINAPI restore_echo_on_ctrl(DWORD) {
    if (g_echo_off) {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), g_saved_input_mode);
    }
    return FALSE;
}

std::string read_from_console(HANDLE in, bool echo) {
    DWORD mode = 0;
    GetConsoleMode(in, &mode);
    if (!echo) {
        g_saved_input_mode = mode;
        g_echo_off = true;
        SetConsoleCtrlHandler(restore_echo_on_ctrl, TRUE);
        SetConsoleMode(in, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    }

    std::wstring line;
    wchar_t buf[256];
    bool ok = true;
    for (;;) {
        DWORD n = 0;
        if (!ReadConsoleW(in, buf, static_cast<DWORD>(std::size(buf)), &n, nullptr) || n == 0) {
            ok = false;
            break;
        }
        line.append(buf, n);
        if (line.back() == L'\n') break;
    }
    SecureZeroMemory(buf, sizeof buf);

    if (!echo) {
        SetConsoleMode(in, mode);
        g_echo_off = false;
        SetConsoleCtrlHandler(restore_echo_on_ctrl, FALSE);
        std::cerr << std::endl;  // the Enter key was not echoed
    }

    while (!line.empty() && (line.back() == L'\n' || line.back() == L'\r')) {
        line.pop_back();
    }
    std::string result = to_utf8(line);
    SecureZeroMemory(line.data(), line.size() * sizeof(wchar_t));
    if (!ok) {
        wipe(result);
        throw std::runtime_error("input ended");
    }
    return result;
}

// Another program may have the clipboard open for a moment; retry briefly.
bool open_clipboard(HWND owner) {
    for (int i = 0; i < 10; ++i) {
        if (OpenClipboard(owner)) return true;
        Sleep(50);
    }
    return false;
}

void set_dword_format(const wchar_t* name, DWORD value) {
    UINT format = RegisterClipboardFormatW(name);
    if (format == 0) return;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
    if (h == nullptr) return;
    *static_cast<DWORD*>(GlobalLock(h)) = value;
    GlobalUnlock(h);
    if (!SetClipboardData(format, h)) {
        GlobalFree(h);
    }
}

bool clear_clipboard_if_unchanged(DWORD seq) {
    if (GetClipboardSequenceNumber() != seq || !open_clipboard(nullptr)) {
        return false;
    }
    EmptyClipboard();
    CloseClipboard();
    return true;
}

// Shared with the Ctrl handler below, which runs on its own thread.
std::atomic<bool> g_stop_waiting{false};
std::atomic<DWORD> g_clipboard_seq{0};

BOOL WINAPI stop_waiting_on_ctrl(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_stop_waiting = true;
        return TRUE;
    }
    // The window is closing or the user is logging off: clear now, there
    // will be no chance later.
    clear_clipboard_if_unchanged(g_clipboard_seq);
    return FALSE;
}

#else

std::string read_from_tty(bool echo) {
    termios old{};
    tcgetattr(STDIN_FILENO, &old);
    if (!echo) {
        termios quiet = old;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    std::string line;
    bool ok = static_cast<bool>(std::getline(std::cin, line));
    if (!echo) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        std::cerr << std::endl;
    }
    if (!ok) {
        throw std::runtime_error("input ended");
    }
    return line;
}

#endif

std::string read_input(std::string_view prompt, bool echo) {
    std::cerr << prompt << std::flush;
#ifdef _WIN32
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(in, &mode)) {
        return read_from_console(in, echo);
    }
#else
    if (isatty(STDIN_FILENO)) {
        return read_from_tty(echo);
    }
#endif
    // Input is piped or redirected: read it as UTF-8 bytes.
    std::string line;
    if (!std::getline(std::cin, line)) {
        throw std::runtime_error("input ended");
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    // PowerShell starts piped text with a UTF-8 byte order mark, which would
    // otherwise become part of the first line (often the master password).
    static bool first_line = true;
    if (first_line && line.starts_with("\xEF\xBB\xBF")) {
        line.erase(0, 3);
    }
    first_line = false;
    return line;
}

}  // namespace

ConsoleTerminal::ConsoleTerminal() {
#ifdef _WIN32
    old_output_cp_ = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
#endif
}

ConsoleTerminal::~ConsoleTerminal() {
#ifdef _WIN32
    if (old_output_cp_ != 0) {
        SetConsoleOutputCP(old_output_cp_);
    }
    if (clipboard_owner_ != nullptr) {
        DestroyWindow(static_cast<HWND>(clipboard_owner_));
    }
#endif
}

std::string ConsoleTerminal::read_line(std::string_view prompt) {
    return read_input(prompt, true);
}

SecretString ConsoleTerminal::read_secret(std::string_view prompt) {
    return SecretString(read_input(prompt, false));
}

std::ostream& ConsoleTerminal::out() { return std::cout; }
std::ostream& ConsoleTerminal::err() { return std::cerr; }

bool ConsoleTerminal::copy_to_clipboard(std::string_view text) {
#ifdef _WIN32
    // A hidden message-only window owns the clipboard data; SetClipboardData
    // is documented to fail when the clipboard has no owner.
    if (clipboard_owner_ == nullptr) {
        clipboard_owner_ = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE,
                                           nullptr, nullptr, nullptr);
    }
    std::wstring w = to_wide(text);
    std::size_t bytes = (w.size() + 1) * sizeof(wchar_t);
    bool ok = false;
    if (open_clipboard(static_cast<HWND>(clipboard_owner_))) {
        EmptyClipboard();
        if (HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes)) {
            std::memcpy(GlobalLock(h), w.c_str(), bytes);
            GlobalUnlock(h);
            if (SetClipboardData(CF_UNICODETEXT, h)) {
                ok = true;
                // Keep the password out of clipboard history (Win+V), cloud
                // clipboard sync and clipboard monitoring tools.
                set_dword_format(L"ExcludeClipboardContentFromMonitorProcessing", 0);
                set_dword_format(L"CanIncludeInClipboardHistory", 0);
                set_dword_format(L"CanUploadToCloudClipboard", 0);
            } else {
                SecureZeroMemory(GlobalLock(h), bytes);
                GlobalUnlock(h);
                GlobalFree(h);
            }
        }
        CloseClipboard();
    }
    SecureZeroMemory(w.data(), w.size() * sizeof(wchar_t));
    clipboard_seq_ = GetClipboardSequenceNumber();
    return ok;
#else
    (void)text;
    return false;
#endif
}

bool ConsoleTerminal::wait_then_clear_clipboard(int seconds) {
#ifdef _WIN32
    g_clipboard_seq = static_cast<DWORD>(clipboard_seq_);
    g_stop_waiting = false;
    SetConsoleCtrlHandler(stop_waiting_on_ctrl, TRUE);
    for (int i = 0; i < seconds * 10 && !g_stop_waiting; ++i) {
        Sleep(100);
    }
    SetConsoleCtrlHandler(stop_waiting_on_ctrl, FALSE);
    return clear_clipboard_if_unchanged(static_cast<DWORD>(clipboard_seq_));
#else
    (void)seconds;
    return false;
#endif
}

std::vector<std::string> command_line_args(int argc, char** argv) {
#ifdef _WIN32
    // argv is in the ANSI code page; ask Windows for the UTF-16 original.
    int n = 0;
    if (LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &n)) {
        std::vector<std::string> args;
        for (int i = 1; i < n; ++i) {
            args.push_back(to_utf8(wargv[i]));
        }
        LocalFree(wargv);
        return args;
    }
#endif
    return std::vector<std::string>(argv + 1, argv + argc);
}

}  // namespace pm
