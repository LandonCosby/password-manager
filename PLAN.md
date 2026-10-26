# Plan

Build a command-line password manager first, then add features in layers.
Each phase should leave the project building, with passing tests.

## Phase 0: Setup
- [x] Project folders, git repo, `.gitignore`
- [x] CMake build, C++20, MinGW toolchain
- [x] libsodium via FetchContent (pinned commit)
- [x] GoogleTest with a first passing test

## Phase 1: Core data model
- [x] `Entry` struct: id, title, username, password, URL, notes, created/modified timestamps
- [x] `Vault` class: add, get, update, delete, list, search (in memory)
- [x] Save to and load from JSON (nlohmann/json); round-trip tests

## Phase 2: Cryptography
- [x] Derive a key from the master password with Argon2id (`crypto_pwhash`) and a random salt
- [x] Encrypt with XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`), new nonce on every save
- [x] File layout: `[magic][version][KDF params][salt][nonce][ciphertext+tag]`
- [x] Wrong password or tampered file: one clear error, no further detail
- [x] Wipe secrets from memory: the key and decrypted JSON live in `SecureBuffer`
      (`sodium_malloc`), the JSON written for encryption is zeroed
- [ ] Still plain `std::string`: entry fields inside `Vault`, and nlohmann/json's
      temporary copies while parsing. Revisit in Phase 6.
- [x] Temporary hard-coded master password removed in Phase 4

## Phase 3: File handling
- [x] Atomic save: write a temp file, flush, rename over the vault
- [x] Keep the previous version as `vault.pmv.bak`
- [x] Default location `%APPDATA%\passwordManager\vault.pmv`
      (override with `PASSWORDMANAGER_VAULT`)
- [ ] The non-Windows code path (POSIX `fsync`/`rename`, `0600` file mode,
      XDG location) compiles only on Linux/macOS and has not been tested yet

## Phase 4: Command-line interface
- [x] Commands: `init`, `add`, `get`, `list`, `edit`, `delete`, `search`, `change-master`
- [x] Hide typing at password prompts (`SetConsoleMode`)
- [x] Copy to clipboard, clear it after about 30 seconds
- [x] Argument parsing (CLI11 2.4.2)
- [ ] Not testable here: the hidden prompt in a real console window. Try it by
      hand; automated runs only cover piped input
- [ ] Non-Windows: no clipboard support yet (`get` says to use `--show`), and
      hidden input via termios is untested

## Phase 5: Password generator
- [ ] `generate` with length and character-set options, using `randombytes_uniform`
- [ ] Optional: passphrase mode from a word list
- [ ] Optional: strength estimate based on entropy

## Phase 6: Hardening and polish
- [ ] Auto-lock after inactivity in interactive mode
- [ ] Delay after failed password attempts
- [ ] CSV import/export, with a warning that exports are plaintext
- [ ] Fuzz-test the vault loader
- [ ] Clean under full warnings and AddressSanitizer

## Phase 7: Optional extensions
- [ ] Graphical app (Qt or Dear ImGui)
- [ ] TOTP (2FA code) support per entry
- [ ] Sync through a cloud-synced folder
- [ ] Secure notes and custom fields
