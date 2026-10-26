#pragma once

#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "crypto.h"

namespace pm {

// Everything the commands need from the outside world, so tests can
// replace it with a scripted fake.
class Terminal {
public:
    virtual ~Terminal() = default;

    // Shows the prompt and reads one line, without the line ending.
    // Throws std::runtime_error at end of input.
    virtual std::string read_line(std::string_view prompt) = 0;

    // Like read_line, but what is typed is not shown.
    virtual SecretString read_secret(std::string_view prompt) = 0;

    virtual std::ostream& out() = 0;
    virtual std::ostream& err() = 0;

    // Puts text on the clipboard, kept out of clipboard history and cloud
    // sync. Returns false if the clipboard cannot be used.
    virtual bool copy_to_clipboard(std::string_view text) = 0;

    // Waits up to the given time (less if the user presses Ctrl+C), then
    // clears the clipboard unless something else was copied since.
    // Returns true if it cleared it.
    virtual bool wait_then_clear_clipboard(int seconds) = 0;
};

// The real console. Prompts go to stderr so that stdout can be redirected.
// On Windows it switches console output to UTF-8 for its lifetime and reads
// input as UTF-16, so a password with non-ASCII characters produces the
// same bytes whatever the console code page is.
class ConsoleTerminal : public Terminal {
public:
    ConsoleTerminal();
    ~ConsoleTerminal() override;
    ConsoleTerminal(const ConsoleTerminal&) = delete;
    ConsoleTerminal& operator=(const ConsoleTerminal&) = delete;

    std::string read_line(std::string_view prompt) override;
    SecretString read_secret(std::string_view prompt) override;
    std::ostream& out() override;
    std::ostream& err() override;
    bool copy_to_clipboard(std::string_view text) override;
    bool wait_then_clear_clipboard(int seconds) override;

private:
    unsigned old_output_cp_ = 0;
    unsigned long clipboard_seq_ = 0;
    void* clipboard_owner_ = nullptr;  // HWND on Windows
};

// The program's arguments as UTF-8, without the program name.
std::vector<std::string> command_line_args(int argc, char** argv);

}  // namespace pm
