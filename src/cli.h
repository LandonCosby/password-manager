#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "crypto.h"
#include "terminal.h"

namespace pm {

inline constexpr std::string_view kVersion = "0.2.0";

// Runs one command, e.g. {"add", "GitHub", "-u", "landon"}, without the
// program name. Returns the process exit code. Tests pass fast KDF settings;
// vaults that already exist are always opened with the settings in the file.
int run_cli(const std::vector<std::string>& args, Terminal& term,
            const KdfParams& kdf = KdfParams::defaults());

}  // namespace pm
