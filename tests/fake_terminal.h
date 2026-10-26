#pragma once

#include <deque>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "terminal.h"

// A Terminal that answers prompts from a script and records everything.
class FakeTerminal : public pm::Terminal {
public:
    explicit FakeTerminal(std::vector<std::string> input = {})
        : input_(input.begin(), input.end()) {}

    std::string read_line(std::string_view prompt) override {
        prompts.emplace_back(prompt);
        return next(prompt);
    }

    pm::SecretString read_secret(std::string_view prompt) override {
        prompts.emplace_back(prompt);
        secret_prompts.emplace_back(prompt);
        return pm::SecretString(next(prompt));
    }

    std::ostream& out() override { return out_; }
    std::ostream& err() override { return err_; }

    bool copy_to_clipboard(std::string_view text) override {
        if (!clipboard_supported) return false;
        clipboard = text;
        return true;
    }

    bool wait_then_clear_clipboard(int seconds) override {
        waited_seconds = seconds;
        clipboard.clear();
        return true;
    }

    std::string output() const { return out_.str(); }
    std::string errors() const { return err_.str(); }
    std::size_t unused_input() const { return input_.size(); }

    std::vector<std::string> prompts;
    std::vector<std::string> secret_prompts;
    bool clipboard_supported = true;
    std::string clipboard;
    int waited_seconds = -1;

private:
    std::string next(std::string_view prompt) {
        if (input_.empty()) {
            throw std::runtime_error("input ended (at prompt '" + std::string(prompt) + "')");
        }
        std::string line = input_.front();
        input_.pop_front();
        return line;
    }

    std::deque<std::string> input_;
    std::ostringstream out_;
    std::ostringstream err_;
};
