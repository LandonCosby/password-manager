# passwordManager

A command-line password manager written in C++20. Vaults are encrypted with
libsodium: Argon2id derives a key from the master password, and
XChaCha20-Poly1305 encrypts the vault.

Status: project setup only. See [PLAN.md](PLAN.md) for the roadmap.

## Requirements

- CMake 3.14+
- A C++20 compiler (tested with MinGW-w64 g++ 16.2 in `C:\dev\mingw64`)
- git (CMake uses it to fetch libsodium and GoogleTest)

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
src/        core library (pm_core) and main.cpp
tests/      GoogleTest unit tests
```
