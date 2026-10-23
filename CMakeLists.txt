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
add_library(pm_core src/crypto.cpp)
target_include_directories(pm_core PUBLIC src)
target_link_libraries(pm_core PUBLIC sodium)
target_compile_options(pm_core PRIVATE ${PM_WARNINGS})

add_executable(password_manager src/main.cpp)
target_link_libraries(password_manager PRIVATE pm_core)
target_compile_options(password_manager PRIVATE ${PM_WARNINGS})

enable_testing()
add_executable(pm_tests tests/test_crypto.cpp)
target_link_libraries(pm_tests PRIVATE pm_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(pm_tests)
