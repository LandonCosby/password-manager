# passwordManager

A command-line password manager written in C++20. Vaults are encrypted with
libsodium: Argon2id derives a key from the master password, and
XChaCha20-Poly1305 encrypts the vault.

Status: encrypted vault with safe saves done. The program creates or opens
the vault and reports how many entries it has. **For development the master
password is hard-coded as `Password1234`** (see `src/main.cpp`); a password
prompt comes in Phase 4. See [PLAN.md](PLAN.md) for the roadmap.

## Vault location

By default the vault is `%APPDATA%\passwordManager\vault.pmv`. Set
`PASSWORDMANAGER_VAULT` to use a different file:

```powershell
$env:PASSWORDMANAGER_VAULT = "C:\temp\test.pmv"
```

Every save copies the previous vault to `vault.pmv.bak` first. Both files
are written to a `.tmp` file, flushed to disk and then renamed into place,
so a crash mid-save leaves complete files.

## Requirements

- CMake 3.14+
- A C++20 compiler (tested with MinGW-w64 g++ 16.2 in `C:\dev\mingw64`)
- git (CMake uses it to fetch libsodium, nlohmann/json and GoogleTest)

## Build

```powershell
$env:PATH = "C:\dev\mingw64\bin;$env:PATH"
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j 8
```

The first configure step takes about a minute because it downloads libsodium
and GoogleTest. The first build compiles libsodium from source.

## Run

```powershell
.\build\password_manager.exe
```

## Test

```powershell
ctest --test-dir build --output-on-failure
```

## Layout

```
src/
  entry.h         Entry: one saved login
  vault.h/.cpp    Vault: in-memory add, find, update, remove, search
  vault_json.*    to_json / from_json (plaintext; encrypted before saving)
  vault_file.*    encrypted file format, save_vault / load_vault, backups
  file_io.*       atomic file writes, default vault location
  crypto.*        libsodium setup, Argon2id key derivation, SecureBuffer
  main.cpp        program entry point
tests/            GoogleTest unit tests
```
