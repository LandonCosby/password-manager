#pragma once

#include <cstdint>
#include <string>

namespace pm {

// One saved login. Timestamps are Unix time in seconds.
struct Entry {
    std::string id;
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    std::int64_t created = 0;
    std::int64_t modified = 0;

    bool operator==(const Entry&) const = default;
};

}  // namespace pm
