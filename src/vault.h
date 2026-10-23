#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "entry.h"

namespace pm {

// Returns the current Unix time in seconds. Tests pass their own clock.
using Clock = std::function<std::int64_t()>;
std::int64_t system_now();

// An in-memory collection of entries. Saving and encryption live elsewhere.
class Vault {
public:
    explicit Vault(Clock clock = system_now);

    // Builds a vault from entries that already have ids and timestamps,
    // e.g. ones loaded from a file. Throws std::invalid_argument if an id
    // is empty or appears twice.
    Vault(std::vector<Entry> entries, Clock clock = system_now);

    // Adds a new entry. Its id and timestamps are filled in, overwriting
    // whatever the caller set. Returns the new id.
    std::string add(Entry entry);

    // Returns the entry with this id, or nullptr. The pointer is valid
    // until the vault is next changed.
    const Entry* find(std::string_view id) const;

    // Replaces the entry with the same id, keeping its created time and
    // setting its modified time. Returns false if there is no such entry.
    bool update(const Entry& entry);

    // Removes the entry with this id. Returns false if there is none.
    bool remove(std::string_view id);

    // Entries whose title, username or URL contain the query, ignoring
    // case. An empty query matches everything.
    std::vector<const Entry*> search(std::string_view query) const;

    const std::vector<Entry>& entries() const { return entries_; }
    std::size_t size() const { return entries_.size(); }

private:
    std::vector<Entry>::iterator find_it(std::string_view id);

    std::vector<Entry> entries_;
    Clock clock_;
};

}  // namespace pm
