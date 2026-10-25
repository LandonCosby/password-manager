#include <filesystem>
#include <iostream>
#include <string_view>

#include "crypto.h"
#include "file_io.h"
#include "vault_file.h"

namespace {

// TODO(Phase 4): replace with a hidden password prompt. This is a
// development placeholder only; never ship a hard-coded master password.
constexpr std::string_view kDevMasterPassword = "Password1234";

}  // namespace

int main() {
    if (!pm::init_crypto()) {
        std::cerr << "error: failed to initialize crypto library\n";
        return 1;
    }
    std::cout << "passwordManager 0.1.0\n";

    try {
        std::filesystem::path vault_path = pm::default_vault_path();
        if (std::filesystem::exists(vault_path)) {
            pm::Vault vault = pm::load_vault(vault_path, kDevMasterPassword);
            std::cout << "Opened " << vault_path.string() << " (" << vault.size()
                      << " entries)\n";
        } else {
            if (vault_path.has_parent_path()) {
                std::filesystem::create_directories(vault_path.parent_path());
            }
            pm::save_vault(vault_path, pm::Vault{}, kDevMasterPassword);
            std::cout << "Created empty vault " << vault_path.string() << "\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
