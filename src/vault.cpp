#include "vault.h"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace pm {

namespace {

// 16 random bytes as 32 hex characters.
std::string new_id() {
    unsigned char bytes[16];
    randombytes_buf(bytes, sizeof bytes);
    char hex[sizeof bytes * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, bytes, sizeof bytes);
    return hex;
}

bool contains_ignore_case(std::string_view haystack, std::string_view needle) {
    auto lower_eq = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    };
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end(), lower_eq) != haystack.end();
}

}  // namespace

std::int64_t system_now() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

Vault::Vault(Clock clock) : clock_(std::move(clock)) {}

Vault::Vault(std::vector<Entry> entries, Clock clock)
    : entries_(std::move(entries)), clock_(std::move(clock)) {
    std::unordered_set<std::string_view> seen;
    for (const Entry& e : entries_) {
        if (e.id.empty()) {
            throw std::invalid_argument("entry has an empty id");
        }
        if (!seen.insert(e.id).second) {
            throw std::invalid_argument("duplicate entry id: " + e.id);
        }
    }
}

std::string Vault::add(Entry entry) {
    entry.id = new_id();
    entry.created = entry.modified = clock_();
    entries_.push_back(std::move(entry));
    return entries_.back().id;
}

const Entry* Vault::find(std::string_view id) const {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [id](const Entry& e) { return e.id == id; });
    return it == entries_.end() ? nullptr : &*it;
}

std::vector<Entry>::iterator Vault::find_it(std::string_view id) {
    return std::find_if(entries_.begin(), entries_.end(),
                        [id](const Entry& e) { return e.id == id; });
}

bool Vault::update(const Entry& entry) {
    auto it = find_it(entry.id);
    if (it == entries_.end()) {
        return false;
    }
    std::int64_t created = it->created;
    *it = entry;
    it->created = created;
    it->modified = clock_();
    return true;
}

bool Vault::remove(std::string_view id) {
    auto it = find_it(id);
    if (it == entries_.end()) {
        return false;
    }
    entries_.erase(it);
    return true;
}

std::vector<const Entry*> Vault::search(std::string_view query) const {
    std::vector<const Entry*> matches;
    for (const Entry& e : entries_) {
        if (contains_ignore_case(e.title, query) ||
            contains_ignore_case(e.username, query) ||
            contains_ignore_case(e.url, query)) {
            matches.push_back(&e);
        }
    }
    return matches;
}

}  // namespace pm
