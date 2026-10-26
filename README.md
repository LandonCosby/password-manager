# passwordManager

A command-line password manager written in C++20. Vaults are encrypted with
libsodium: Argon2id derives a key from the master password, and
XChaCha20-Poly1305 encrypts the vault.

Status: usable from the command line. A password generator comes next; see
[PLAN.md](PLAN.md) for the roadmap.

## Usage

```powershell
password_manager init                      # create a vault, choose a master password
password_manager add GitHub -u landon      # asks for the password, URL and notes
password_manager list
password_manager search git
password_manager get GitHub                # copies the password for 30 seconds
password_manager get GitHub --show         # prints it instead
password_manager edit GitHub
password_manager delete GitHub
password_manager change-master
password_manager --help                    # all options
```

Every command asks for the master password at a hidden prompt. Passwords are
never taken as command-line arguments, so they do not end up in shell
history.

`get`, `edit` and `delete` take an exact title, the start of an ID (as shown
by `list`) or search text; if more than one entry matches, they list the
matches and ask you to use an ID.

Copied passwords are kept out of Windows clipboard history (Win+V) and cloud
clipboard sync, and are cleared after 30 seconds, on Ctrl+C, or when the
window is closed, unless you have copied something else since.

Prompts go to stderr, so `get --show > file` captures only the entry. Input
can be piped for scripting; one answer per line, in prompt order.

Note for Windows PowerShell 5.1: it silently drops empty `""` arguments, so
leave out an option such as `--url ""` instead of passing an empty value.

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
- git (CMake uses it to fetch libsodium, nlohmann/json, CLI11 and GoogleTest)

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
.\build\password_manager.exe --help
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
  crypto.*        libsodium setup, Argon2id key derivation, SecureBuffer,
                  SecretString
  cli.*           the commands (run_cli)
  terminal.*      Terminal interface; ConsoleTerminal: hidden input,
                  clipboard, UTF-8 arguments
  main.cpp        program entry point
tests/            GoogleTest unit tests (FakeTerminal scripts the prompts)
```
