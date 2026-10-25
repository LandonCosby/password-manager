#pragma once

#include <filesystem>
#include <span>
#include <vector>

namespace pm {

// Reads a whole file. Throws std::runtime_error if it cannot be read.
std::vector<unsigned char> read_file(const std::filesystem::path& path);

// Replaces the file at path with data so that a crash or power cut at any
// point leaves either the old contents or the new ones, never a mix.
//
// The data goes to path + ".tmp" in the same folder, is flushed to disk,
// and the temp file is then renamed over path. Throws std::runtime_error
// on failure, in which case path is unchanged and the temp file removed.
void write_file_atomic(const std::filesystem::path& path,
                       std::span<const unsigned char> data);

// Where the vault lives unless told otherwise:
//   1. $PASSWORDMANAGER_VAULT, if set (useful for testing)
//   2. Windows: %APPDATA%\passwordManager\vault.pmv
//      Elsewhere: $XDG_DATA_HOME/passwordManager/vault.pmv, falling back
//      to ~/.local/share/passwordManager/vault.pmv
// Throws std::runtime_error if none of these variables is set.
std::filesystem::path default_vault_path();

}  // namespace pm
