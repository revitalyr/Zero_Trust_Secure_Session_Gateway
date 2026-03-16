cmake_minimum_required(VERSION 3.20)
project(ZeroTrustSecureSessionGateway VERSION 1.0.0 LANGUAGES CXX)

# Windows-specific definitions
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601) # Windows 7
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable C++23 modules support (when available)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.28")
    # CMake 3.28+ has native module support
    set(CMAKE_CXX_SCAN_FOR_MODULES ON)
    set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)
elseif(MSVC AND MSVC_VERSION GREATER_EQUAL 1934)
    # MSVC 19.34+ supports modules
    add_compile_options(/experimental:module)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "13")
    # GCC 13+ supports modules
    add_compile_options(-fmodules-ts)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "17")
    # Clang 17+ supports modules
    add_compile_options(-fmodules-ts)
endif()

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

# Find readline for the CLI
find_package(Readline QUIET)
if(NOT Readline_FOUND)
    message(STATUS "Readline not found, interactive CLI may have limited features.")
else()
    set(READLINE_INCLUDE_DIR ${Readline_INCLUDE_DIRS})
    set(READLINE_LIBRARIES ${Readline_LIBRARIES})
endif()

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

# Add vcpkg include directories if using vcpkg
if(DEFINED ENV{VCPKG_ROOT})
    include_directories($ENV{VCPKG_ROOT}/installed/x64-windows/include)
endif()

# For C++20 modules, implementation files (.cpp) must be separated from
# module interface files (.ixx).
set(ZEROSSG_IMPL_SOURCES
    "src/auth/authenticator.cpp"
    "src/cli/cli_interface.cpp"
    "src/config/config_manager.cpp"
    "src/logging/logger.cpp"
    "src/network/connection.cpp"
    "src/network/gateway_server.cpp"
    "src/proxy/proxy_manager.cpp"
    "src/rbac/authorizer.cpp"
    "src/security/security_manager.cpp"
    "src/session/session_manager.cpp"
    "src/tls/tls_handler.cpp"
    "src/types.cpp"
)

add_library(zerossg_lib STATIC ${ZEROSSG_IMPL_SOURCES})

# Module interfaces must be declared in a FILE_SET. This allows CMake's
# dependency scanner to correctly identify and build them first.
target_sources(zerossg_lib PUBLIC
    FILE_SET CXX_MODULES
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    FILES
        "include/zerossg/auth/authenticator.ixx"
        "include/zerossg/cli/cli_interface.ixx"
        "include/zerossg/common.ixx"
        "include/zerossg/config/config_manager.ixx"
        "include/zerossg/constants.ixx"
        "include/zerossg/interfaces.ixx"
        "include/zerossg/logging/logger.ixx"
        "include/zerossg/network/connection.ixx"
        "include/zerossg/network/gateway_server.ixx"
        "include/zerossg/proxy/proxy_manager.ixx"
        "include/zerossg/rbac/authorizer.ixx"
        "include/zerossg/result.ixx"
        "include/zerossg/security/security_manager.ixx"
        "include/zerossg/session/session_manager.ixx"
        "include/zerossg/std.ixx"
        "include/zerossg/third_party/nlohmann_json.ixx"
        "include/zerossg/third_party/openssl.ixx"
        "include/zerossg/third_party/yaml_cpp.ixx"
        "include/zerossg/tls/tls_handler.ixx"
        "include/zerossg/types.ixx"
)

# Apply compile features and include directories to the library.
# Using PUBLIC ensures that any target linking against zerossg_lib
# will inherit these properties.
target_compile_features(zerossg_lib PUBLIC cxx_std_23)

target_include_directories(zerossg_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# Link all external dependencies to the main library.
# These will be propagated to the final executable and test targets.
target_link_libraries(zerossg_lib PUBLIC
    Boost::system
    ${SPDLOG_LIBRARIES}
    ${NLOHMANN_JSON_LIBRARIES}
    ${YAML_CPP_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${READLINE_LIBRARIES}
)

# Add subdirectories
add_subdirectory(src)

# Enable testing
enable_testing()
add_subdirectory(tests)
