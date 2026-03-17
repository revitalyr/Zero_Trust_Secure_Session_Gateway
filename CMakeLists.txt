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

# Find required packages using modern CMake.
# With the vcpkg toolchain file, these will be found automatically.
find_package(Boost CONFIG REQUIRED COMPONENTS system thread) 

if(Boost_FOUND)
    message(STATUS "Boost found: ${Boost_VERSION}")
endif()

find_package(spdlog REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(yaml-cpp REQUIRED)

find_package(OpenSSL REQUIRED)

find_package(Readline) # Not required, can be optional

if(Readline_FOUND)
    message(STATUS "Readline found, enabling interactive mode features.")
    # This definition will be used to conditionally compile readline-dependent code.
    target_compile_definitions(zerossg_lib PUBLIC HAVE_READLINE)
else()
    message(STATUS "Readline not found, interactive CLI may have limited features.")
endif()

# For C++20 modules, implementation files (.cpp) must be separated from
# module interface files (.ixx).
# Note: When using modules, implementation units can also be part of the module
# but for now we compile them as regular sources that likely 'import' the modules.
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
        "include/zerossg/security/security_manager.ixx"
        "include/zerossg/session/session_manager.ixx"
        "include/zerossg/std.ixx"
        "include/zerossg/network.ixx"
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

# Modern way to set compiler-specific flags using generator expressions
target_compile_options(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX /utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror -fstack-protector-strong>
)
target_compile_definitions(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:_FORTIFY_SOURCE=2>
)

# Include directories are handled by find_package and target_link_libraries
target_include_directories(zerossg_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Link all external dependencies to the main library.
# These will be propagated to the final executable and test targets.
target_link_libraries(zerossg_lib PUBLIC
    Boost::system
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
    OpenSSL::SSL
    OpenSSL::Crypto
)
if(Readline_FOUND)
    # Link Readline if it was found
    target_link_libraries(zerossg_lib PUBLIC Readline::Readline)
endif()

# Add subdirectories
add_subdirectory(src)

# Enable testing
enable_testing()
add_subdirectory(tests)
