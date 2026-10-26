#include "cli.h"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "file_io.h"
#include "vault_file.h"

namespace pm {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kMinMasterLength = 8;
constexpr int kClipboardSeconds = 30;
constexpr std::size_t kShortIdLength = 8;
constexpr std::size_t kMinIdPrefix = 4;

// A problem with what the user asked for, reported as a one-line error.
class UserError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string trim(std::string_view s) {
    auto space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && space(s.front())) s.remove_prefix(1);
    while (!s.empty() && space(s.back())) s.remove_suffix(1);
    return std::string(s);
}

// std::filesystem treats a narrow string as the ANSI code page on Windows;
// everything in this program is UTF-8.
fs::path path_from_utf8(const std::string& s) {
    return fs::path(std::u8string(s.begin(), s.end()));
}

std::string display(const fs::path& p) {
    std::u8string u = p.u8string();
    return std::string(u.begin(), u.end());
}

std::string short_id(const Entry& e) {
    return e.id.substr(0, kShortIdLength);
}

std::string format_time(std::int64_t t) {
    using namespace std::chrono;
    return std::format("{:%Y-%m-%d %H:%M} UTC", sys_seconds{seconds{t}});
}

void print_table(std::ostream& out, std::vector<const Entry*> entries) {
    std::sort(entries.begin(), entries.end(), [](const Entry* a, const Entry* b) {
        return std::pair(lower(a->title), a->id) < std::pair(lower(b->title), b->id);
    });
    std::size_t title_w = 5, user_w = 8;  // "TITLE", "USERNAME"
    for (const Entry* e : entries) {
        title_w = std::max(title_w, e->title.size());
        user_w = std::max(user_w, e->username.size());
    }
    auto row = [&](std::string_view id, std::string_view title, std::string_view user,
                   std::string_view url) {
        std::string line = std::format("{:<{}}  {:<{}}  {:<{}}  {}", id, kShortIdLength, title,
                                       title_w, user, user_w, url);
        out << trim(line) << "\n";
    };
    row("ID", "TITLE", "USERNAME", "URL");
    for (const Entry* e : entries) {
        row(short_id(*e), e->title, e->username, e->url);
    }
}

void print_entry(std::ostream& out, const Entry& e) {
    out << "Title:    " << e.title << "\n";
    if (!e.username.empty()) out << "Username: " << e.username << "\n";
    if (!e.url.empty()) out << "URL:      " << e.url << "\n";
    if (!e.notes.empty()) out << "Notes:    " << e.notes << "\n";
    out << "ID:       " << e.id << "\n"
        << "Created:  " << format_time(e.created) << "\n"
        << "Modified: " << format_time(e.modified) << "\n";
}

// Asks twice and checks both answers match.
SecretString read_new_secret(Terminal& t, std::string_view label, std::size_t min_length,
                             std::string_view too_short) {
    SecretString first = t.read_secret(std::string(label) + ": ");
    if (first.size() < min_length) {
        throw UserError(std::string(too_short));
    }
    std::string repeat = "Repeat " + lower(label) + ": ";
    SecretString second = t.read_secret(repeat);
    if (first.str() != second.str()) {
        throw UserError("the passwords do not match");
    }
    return first;
}

SecretString read_new_master(Terminal& t) {
    return read_new_secret(t, "New master password", kMinMasterLength,
                           "the master password must be at least 8 characters");
}

SecretString read_entry_password(Terminal& t) {
    return read_new_secret(t, "Password", 1, "the password must not be empty");
}

bool ask_yes_no(Terminal& t, std::string_view prompt) {
    std::string answer = lower(trim(t.read_line(prompt)));
    return answer == "y" || answer == "yes";
}

// Shows the current value; Enter keeps it and "-" clears it.
std::string keep_or_change(Terminal& t, std::string_view label, const std::string& current) {
    std::string prompt = current.empty() ? std::format("{}: ", label)
                                         : std::format("{} [{}]: ", label, current);
    std::string answer = t.read_line(prompt);
    if (answer.empty()) return current;
    if (answer == "-") return "";
    return answer;
}

struct Session {
    fs::path path;
    Vault vault;
    SecretString master;
};

Session unlock(const fs::path& path, Terminal& t) {
    if (!fs::exists(path)) {
        throw UserError("no vault at " + display(path) +
                        "; run 'password_manager init' to create one");
    }
    SecretString master = t.read_secret("Master password: ");
    Vault vault = load_vault(path, master.view());
    return {path, std::move(vault), std::move(master)};
}

void save(const Session& s, const KdfParams& kdf) {
    save_vault(s.path, s.vault, s.master.view(), kdf);
}

// Finds one entry by, in order: exact title (ignoring case), id prefix,
// then a search of title, username and URL.
const Entry& resolve(const Vault& vault, std::string_view query) {
    std::vector<const Entry*> matches;
    std::string q = lower(query);
    for (const Entry& e : vault.entries()) {
        if (lower(e.title) == q) matches.push_back(&e);
    }
    if (matches.empty() && q.size() >= kMinIdPrefix) {
        for (const Entry& e : vault.entries()) {
            if (e.id.starts_with(q)) matches.push_back(&e);
        }
    }
    if (matches.empty()) {
        matches = vault.search(query);
    }

    if (matches.empty()) {
        throw UserError(std::format("no entry matches '{}'", query));
    }
    if (matches.size() > 1) {
        std::ostringstream list;
        print_table(list, matches);
        throw UserError(std::format("'{}' matches {} entries; use an ID instead:\n{}", query,
                                    matches.size(), trim(list.str())));
    }
    return *matches.front();
}

int cmd_init(const fs::path& path, Terminal& t, const KdfParams& kdf) {
    if (fs::exists(path)) {
        throw UserError("a vault already exists at " + display(path));
    }
    SecretString master = read_new_master(t);
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }
    save_vault(path, Vault{}, master.view(), kdf);
    t.out() << "Created vault at " << display(path) << "\n";
    return 0;
}

struct AddArgs {
    std::string title;
    std::optional<std::string> username, url, notes;
};

int cmd_add(const fs::path& path, Terminal& t, const KdfParams& kdf, const AddArgs& a) {
    Session s = unlock(path, t);
    Entry e;
    e.title = a.title;
    e.username = a.username ? *a.username : t.read_line("Username: ");
    SecretString password = read_entry_password(t);
    e.password = password.str();
    e.url = a.url ? *a.url : t.read_line("URL (optional): ");
    e.notes = a.notes ? *a.notes : t.read_line("Notes (optional): ");

    std::string id = s.vault.add(e);
    wipe(e.password);
    save(s, kdf);
    t.out() << std::format("Added '{}' ({})\n", a.title, id.substr(0, kShortIdLength));
    return 0;
}

int cmd_get(const fs::path& path, Terminal& t, const std::string& query, bool show) {
    Session s = unlock(path, t);
    const Entry& e = resolve(s.vault, query);
    print_entry(t.out(), e);
    if (show) {
        t.out() << "Password: " << e.password << "\n";
        return 0;
    }
    if (!t.copy_to_clipboard(e.password)) {
        throw UserError("cannot use the clipboard here; use --show to print the password");
    }
    t.out() << std::format(
                   "Password copied to the clipboard. It will be cleared in {} seconds; "
                   "press Ctrl+C to clear it now.\n",
                   kClipboardSeconds)
            << std::flush;
    if (t.wait_then_clear_clipboard(kClipboardSeconds)) {
        t.out() << "Clipboard cleared.\n";
    } else {
        t.out() << "Something else was copied since; clipboard left as it is.\n";
    }
    return 0;
}

int cmd_list(const fs::path& path, Terminal& t) {
    Session s = unlock(path, t);
    if (s.vault.size() == 0) {
        t.out() << "No entries. Add one with 'password_manager add <title>'.\n";
        return 0;
    }
    std::vector<const Entry*> all;
    for (const Entry& e : s.vault.entries()) all.push_back(&e);
    print_table(t.out(), all);
    return 0;
}

int cmd_search(const fs::path& path, Terminal& t, const std::string& query) {
    Session s = unlock(path, t);
    std::vector<const Entry*> matches = s.vault.search(query);
    if (matches.empty()) {
        t.out() << std::format("No entries match '{}'.\n", query);
        return 0;
    }
    print_table(t.out(), matches);
    return 0;
}

int cmd_edit(const fs::path& path, Terminal& t, const KdfParams& kdf, const std::string& query) {
    Session s = unlock(path, t);
    Entry e = resolve(s.vault, query);
    t.out() << std::format("Editing '{}'. Press Enter to keep a value, or type - to clear it.\n",
                           e.title)
            << std::flush;

    e.title = keep_or_change(t, "Title", e.title);
    if (e.title.empty()) {
        throw UserError("the title cannot be empty");
    }
    e.username = keep_or_change(t, "Username", e.username);
    e.url = keep_or_change(t, "URL", e.url);
    e.notes = keep_or_change(t, "Notes", e.notes);
    if (ask_yes_no(t, "Change password? [y/N] ")) {
        SecretString password = read_entry_password(t);
        e.password = password.str();
    }

    s.vault.update(e);
    wipe(e.password);
    save(s, kdf);
    t.out() << std::format("Updated '{}'.\n", e.title);
    return 0;
}

int cmd_delete(const fs::path& path, Terminal& t, const KdfParams& kdf, const std::string& query,
               bool yes) {
    Session s = unlock(path, t);
    const Entry& e = resolve(s.vault, query);
    std::string title = e.title;
    std::string id = e.id;
    if (!yes && !ask_yes_no(t, std::format("Delete '{}'? [y/N] ", title))) {
        t.out() << "Not deleted.\n";
        return 0;
    }
    s.vault.remove(id);
    save(s, kdf);
    t.out() << std::format("Deleted '{}'.\n", title);
    return 0;
}

int cmd_change_master(const fs::path& path, Terminal& t, const KdfParams& kdf) {
    Session s = unlock(path, t);
    SecretString master = read_new_master(t);
    save_vault(s.path, s.vault, master.view(), kdf);
    // save_vault left the old-password file as the backup. The contents are
    // the same, so replace it: the old password should open nothing.
    write_file_atomic(backup_path(s.path), read_file(s.path));
    t.out() << "Master password changed.\n";
    return 0;
}

}  // namespace

int run_cli(const std::vector<std::string>& args, Terminal& term, const KdfParams& kdf) {
    CLI::App app{"An encrypted password vault.", "password_manager"};
    app.set_version_flag("--version", "passwordManager " + std::string(kVersion));
    app.require_subcommand(1);
    app.fallthrough();

    std::string vault_arg;
    app.add_option("--vault", vault_arg,
                   "Vault file (default: $PASSWORDMANAGER_VAULT, else "
                   "%APPDATA%\\passwordManager\\vault.pmv)");

    CLI::App* init = app.add_subcommand("init", "Create a new, empty vault");

    AddArgs add_args;
    std::string add_username, add_url, add_notes;
    CLI::App* add = app.add_subcommand("add", "Add an entry (the password is always prompted for)");
    add->add_option("title", add_args.title, "Name of the site or account")->required();
    CLI::Option* add_username_opt =
        add->add_option("-u,--username", add_username, "Username (asked for if left out)");
    CLI::Option* add_url_opt = add->add_option("--url", add_url, "URL (asked for if left out)");
    CLI::Option* add_notes_opt =
        add->add_option("--notes", add_notes, "Notes (asked for if left out)");

    std::string query;
    bool show = false;
    CLI::App* get = app.add_subcommand(
        "get", "Show an entry and copy its password to the clipboard for 30 seconds");
    get->add_option("query", query, "Title, ID or search text")->required();
    get->add_flag("--show", show, "Print the password instead of copying it");

    CLI::App* list = app.add_subcommand("list", "List all entries");

    CLI::App* search = app.add_subcommand("search", "List entries whose title, username or URL match");
    search->add_option("query", query, "Text to look for (case is ignored)")->required();

    CLI::App* edit = app.add_subcommand("edit", "Change an entry");
    edit->add_option("query", query, "Title, ID or search text")->required();

    bool yes = false;
    CLI::App* del = app.add_subcommand("delete", "Delete an entry");
    del->add_option("query", query, "Title, ID or search text")->required();
    del->add_flag("-y,--yes", yes, "Do not ask for confirmation");

    CLI::App* change_master =
        app.add_subcommand("change-master", "Change the master password");

    std::vector<const char*> argv{"password_manager"};
    for (const std::string& a : args) {
        argv.push_back(a.c_str());
    }
    try {
        app.parse(static_cast<int>(argv.size()), argv.data());
    } catch (const CLI::ParseError& e) {
        return app.exit(e, term.out(), term.err());
    }

    try {
        fs::path path = vault_arg.empty() ? default_vault_path() : path_from_utf8(vault_arg);
        if (init->parsed()) return cmd_init(path, term, kdf);
        if (add->parsed()) {
            if (add_username_opt->count()) add_args.username = add_username;
            if (add_url_opt->count()) add_args.url = add_url;
            if (add_notes_opt->count()) add_args.notes = add_notes;
            return cmd_add(path, term, kdf, add_args);
        }
        if (get->parsed()) return cmd_get(path, term, query, show);
        if (list->parsed()) return cmd_list(path, term);
        if (search->parsed()) return cmd_search(path, term, query);
        if (edit->parsed()) return cmd_edit(path, term, kdf, query);
        if (del->parsed()) return cmd_delete(path, term, kdf, query, yes);
        if (change_master->parsed()) return cmd_change_master(path, term, kdf);
    } catch (const std::exception& ex) {
        term.err() << "error: " << ex.what() << "\n";
        return 1;
    }
    return 1;  // unreachable: require_subcommand(1)
}

}  // namespace pm
