# Plan

Build a command-line password manager first, then add features in layers.
Each phase should leave the project building, with passing tests.

## Phase 0: Setup
- [x] Project folders, git repo, `.gitignore`
- [x] CMake build, C++20, MinGW toolchain
- [x] libsodium via FetchContent (pinned commit)
- [x] GoogleTest with a first passing test

## Phase 1: Core data model
- [ ] `Entry` struct: id, title, username, password, URL, notes, created/modified timestamps
- [ ] `Vault` class: add, get, update, delete, list, search (in memory)
- [ ] Save to and load from JSON (nlohmann/json); round-trip tests

## Phase 2: Cryptography
- [ ] Derive a key from the master password with Argon2id (`crypto_pwhash`) and a random salt
- [ ] Encrypt with XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf`), new nonce on every save
- [ ] File layout: `[magic][version][KDF params][salt][nonce][ciphertext+tag]`
- [ ] Wrong password or tampered file: one clear error, no further detail
- [ ] Wipe secrets from memory (`sodium_memzero`, `sodium_mlock`, a `SecureString` wrapper)

## Phase 3: File handling
- [ ] Atomic save: write a temp file, flush, rename over the vault
- [ ] Keep the previous version as `vault.pmv.bak`
- [ ] Default location `%APPDATA%\passwordManager\vault.pmv`

## Phase 4: Command-line interface
- [ ] Commands: `init`, `add`, `get`, `list`, `edit`, `delete`, `search`, `change-master`
- [ ] Hide typing at password prompts (`SetConsoleMode`)
- [ ] Copy to clipboard, clear it after about 30 seconds
- [ ] Argument parsing (CLI11 or a simple hand-written parser)

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
