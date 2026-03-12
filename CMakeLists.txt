cmake_minimum_required(VERSION 3.20)
project(ZeroTrustSecureSessionGateway VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags for security and performance
if(MSVC)
    add_compile_options(/W4 /WX /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    add_compile_options(-fstack-protector-strong)
    add_compile_options(-D_FORTIFY_SOURCE=2)
endif()

# Find required packages with modern CMake
find_package(Boost 1.75 REQUIRED COMPONENTS system)

# Use system packages with fallback
find_package(spdlog QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "Using vcpkg for spdlog...")
    set(SPDLOG_INCLUDE_DIR $ENV{VCPKG_ROOT}/installed/x64-windows/include)
    set(SPDLOG_LIBRARIES spdlog)
else()
    set(SPDLOG_INCLUDE_DIR ${spdlog_INCLUDE_DIRS})
    set(SPDLOG_LIBRARIES ${spdlog_LIBRARIES})
endif()

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "Using vcpkg for nlohmann_json...")
    set(NLOHMANN_JSON_INCLUDE_DIR $ENV{VCPKG_ROOT}/installed/x64-windows/include)
    set(NLOHMANN_JSON_LIBRARIES nlohmann_json)
else()
    set(NLOHMANN_JSON_INCLUDE_DIR ${nlohmann_json_INCLUDE_DIRS})
    set(NLOHMANN_JSON_LIBRARIES ${nlohmann_json_LIBRARIES})
endif()

find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    message(STATUS "Using vcpkg for yaml-cpp...")
    set(YAML_CPP_INCLUDE_DIR $ENV{VCPKG_ROOT}/installed/x64-windows/include)
    set(YAML_CPP_LIBRARIES yaml-cpp)
else()
    set(YAML_CPP_INCLUDE_DIR ${yaml-cpp_INCLUDE_DIRS})
    set(YAML_CPP_LIBRARIES ${yaml-cpp_LIBRARIES})
endif()

find_package(OpenSSL QUIET)
if(NOT OpenSSL_FOUND)
    message(STATUS "Using vcpkg for OpenSSL...")
    set(OPENSSL_INCLUDE_DIR $ENV{VCPKG_ROOT}/installed/x64-windows/include)
    set(OPENSSL_LIBRARIES ssl crypto)
else()
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES})
endif()

# Include directories
include_directories(include)
include_directories(${Boost_INCLUDE_DIRS})

# Add subdirectories
add_subdirectory(src)

# Enable testing
enable_testing()
add_subdirectory(tests)
