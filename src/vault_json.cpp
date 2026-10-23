#include "vault_json.h"

#include <nlohmann/json.hpp>

#include <utility>
#include <vector>

namespace pm {

using nlohmann::json;

std::string to_json(const Vault& vault) {
    json entries = json::array();
    for (const Entry& e : vault.entries()) {
        entries.push_back({
            {"id", e.id},
            {"title", e.title},
            {"username", e.username},
            {"password", e.password},
            {"url", e.url},
            {"notes", e.notes},
            {"created", e.created},
            {"modified", e.modified},
        });
    }
    json doc = {{"version", kVaultJsonVersion}, {"entries", std::move(entries)}};
    return doc.dump();
}

Vault from_json(std::string_view text, Clock clock) {
    std::vector<Entry> entries;
    try {
        json doc = json::parse(text);
        int version = doc.at("version").get<int>();
        if (version != kVaultJsonVersion) {
            throw FormatError("unsupported vault version " + std::to_string(version));
        }
        const json& list = doc.at("entries");
        if (!list.is_array()) {
            throw FormatError("invalid vault JSON: entries is not an array");
        }
        for (const json& j : list) {
            Entry e;
            j.at("id").get_to(e.id);
            j.at("title").get_to(e.title);
            j.at("username").get_to(e.username);
            j.at("password").get_to(e.password);
            j.at("url").get_to(e.url);
            j.at("notes").get_to(e.notes);
            j.at("created").get_to(e.created);
            j.at("modified").get_to(e.modified);
            entries.push_back(std::move(e));
        }
    } catch (const json::exception& ex) {
        throw FormatError(std::string("invalid vault JSON: ") + ex.what());
    }

    try {
        return Vault(std::move(entries), std::move(clock));
    } catch (const std::invalid_argument& ex) {
        throw FormatError(std::string("invalid vault JSON: ") + ex.what());
    }
}

}  // namespace pm
