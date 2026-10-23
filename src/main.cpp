#include <filesystem>
#include <iostream>
#include <string_view>

#include "crypto.h"
#include "vault_file.h"

namespace {

// TODO(Phase 4): replace with a hidden password prompt. This is a
// development placeholder only; never ship a hard-coded master password.
constexpr std::string_view kDevMasterPassword = "Password1234";

// TODO(Phase 3): move to %APPDATA%\passwordManager\vault.pmv.
const std::filesystem::path kVaultPath = "vault.pmv";

}  // namespace

int main() {
    if (!pm::init_crypto()) {
        std::cerr << "error: failed to initialize crypto library\n";
        return 1;
    }
    std::cout << "passwordManager 0.1.0\n";

    try {
        if (std::filesystem::exists(kVaultPath)) {
            pm::Vault vault = pm::load_vault(kVaultPath, kDevMasterPassword);
            std::cout << "Opened " << kVaultPath.string() << " (" << vault.size()
                      << " entries)\n";
        } else {
            pm::save_vault(kVaultPath, pm::Vault{}, kDevMasterPassword);
            std::cout << "Created empty vault " << kVaultPath.string() << "\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
