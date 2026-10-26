cmake_minimum_required(VERSION 3.14)
project(password_manager CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# libsodium, built from source through a CMake wrapper because the
# MinGW toolchain has no prebuilt package.
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG 9b2848dfc1b917a9410f0de9d81059b26cbfaa8d
)
FetchContent_MakeAvailable(sodium)

# Unoptimized Argon2id is many times slower, which makes opening a vault
# take seconds in Debug builds. Always optimize libsodium itself.
if(NOT MSVC)
  target_compile_options(sodium PRIVATE -O2)
endif()

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(json)

FetchContent_Declare(
  cli11
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG v2.4.2
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(cli11)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(googletest)

if(MSVC)
  set(PM_WARNINGS /W4)
else()
  set(PM_WARNINGS -Wall -Wextra -Wpedantic)
endif()

# Core code lives in a library so the tests can link against it.
add_library(pm_core
  src/crypto.cpp
  src/vault.cpp
  src/vault_json.cpp
  src/vault_file.cpp
  src/file_io.cpp
  src/terminal.cpp
  src/cli.cpp
)
target_include_directories(pm_core PUBLIC src)
target_link_libraries(pm_core
  PUBLIC sodium
  PRIVATE nlohmann_json::nlohmann_json CLI11::CLI11
)
if(WIN32)
  # Clipboard and window functions, and CommandLineToArgvW.
  target_link_libraries(pm_core PRIVATE user32 shell32)
endif()
target_compile_options(pm_core PRIVATE ${PM_WARNINGS})

add_executable(password_manager src/main.cpp)
target_link_libraries(password_manager PRIVATE pm_core)
target_compile_options(password_manager PRIVATE ${PM_WARNINGS})

enable_testing()
add_executable(pm_tests
  tests/test_crypto.cpp
  tests/test_vault.cpp
  tests/test_vault_json.cpp
  tests/test_vault_file.cpp
  tests/test_file_io.cpp
)
target_link_libraries(pm_tests PRIVATE pm_core GTest::gtest_main)
target_compile_options(pm_tests PRIVATE ${PM_WARNINGS})

include(GoogleTest)
gtest_discover_tests(pm_tests)
