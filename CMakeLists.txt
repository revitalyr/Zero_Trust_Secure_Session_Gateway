cmake_minimum_required(VERSION 3.20)
project(ZeroTrustSecureSessionGateway VERSION 1.0.0 LANGUAGES CXX)

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

# C++23 modules support
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.28")
    # CMake 3.28+ has native module support
    set(CMAKE_CXX_SCAN_FOR_MODULES ON)
    set(CMAKE_EXPERIMENTAL_CXX_MODULE_STD ON)
    
    # Create interface library for common
    add_library(zerossg.common INTERFACE 
        include/zerossg/common.ixx
    )
    target_compile_features(zerossg.common INTERFACE cxx_std_23)
    
    # Create interface library for types
    add_library(zerossg.types INTERFACE 
        include/zerossg/types.ixx
    )
    target_compile_features(zerossg.types INTERFACE cxx_std_23)
    target_link_libraries(zerossg.types INTERFACE zerossg.common)
    
    # Create interface library for constants
    add_library(zerossg.constants INTERFACE 
        include/zerossg/constants.ixx
    )
    target_compile_features(zerossg.constants INTERFACE cxx_std_23)
    target_link_libraries(zerossg.constants INTERFACE zerossg.common)
    
    # Create interface library for interfaces
    add_library(zerossg.interfaces INTERFACE 
        include/zerossg/interfaces.ixx
    )
    target_compile_features(zerossg.interfaces INTERFACE cxx_std_23)
    target_link_libraries(zerossg.interfaces INTERFACE zerossg.common zerossg.types)
    
    # Create interface library for authenticator
    add_library(zerossg.auth.authenticator INTERFACE 
        include/zerossg/auth/authenticator.ixx
    )
    target_compile_features(zerossg.auth.authenticator INTERFACE cxx_std_23)
    target_link_libraries(zerossg.auth.authenticator INTERFACE zerossg.common zerossg.types zerossg.interfaces)
    
    # Create interface library for logging
    add_library(zerossg.logging.logger INTERFACE 
        include/zerossg/logging/logger.ixx
    )
    target_compile_features(zerossg.logging.logger INTERFACE cxx_std_23)
    target_link_libraries(zerossg.logging.logger INTERFACE zerossg.common zerossg.interfaces)
endif()

# Add subdirectories
add_subdirectory(src)

# Enable testing
enable_testing()
add_subdirectory(tests)
