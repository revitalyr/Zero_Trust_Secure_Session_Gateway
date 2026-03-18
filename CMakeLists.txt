cmake_minimum_required(VERSION 3.28) # Recommended 3.28+ for stable modules

# 1. SUPPRESS WARNINGS (before project())
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS ON CACHE BOOL "Mute dev warnings" FORCE)
# Suppress old Boost search warnings
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
# Suppress FetchContent_Populate warnings (for CPM/UT)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
# Suppress add_custom_command warnings (for UT)
if(POLICY CMP0175)
    cmake_policy(SET CMP0175 OLD)
endif()

project(ZeroTrustSecureSessionGateway VERSION 1.0.0 LANGUAGES CXX)

# Windows-specific definitions
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601) 
endif()

# 2. STANDARD SETTINGS
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

# 3. DEPENDENCY SEARCH (vcpkg)
# Search Readline (QUIET removes Warning if library not found)
find_package(Readline QUIET)

# Search other dependencies
find_package(Boost REQUIRED COMPONENTS system thread date_time container)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)

# 4. LIBRARY CREATION (MODULES)
add_library(zerossg_lib)

# Add module interface files (.ixx)
target_sources(zerossg_lib
    PUBLIC
        FILE_SET CXX_MODULES FILES
        "include/zerossg/interfaces.ixx"
        "include/zerossg/types.ixx"
        "include/zerossg/constants.ixx"
        "include/zerossg/std.ixx"
        "include/zerossg/common.ixx"
        "include/zerossg/network.ixx"
        "include/zerossg/logging/logger.ixx"
        "include/zerossg/config/config_manager.ixx"
        "include/zerossg/auth/authenticator.ixx"
        "include/zerossg/rbac/authorizer.ixx"
        "include/zerossg/session/session_manager.ixx"
        "include/zerossg/security/security_manager.ixx"
        "include/zerossg/proxy/proxy_manager.ixx"
        "include/zerossg/tls/tls_handler.ixx"
        "include/zerossg/network/gateway_server.ixx"
        "include/zerossg/cli/cli_interface.ixx"
        "include/zerossg/web/web_server.ixx"
        "include/zerossg/third_party/nlohmann_json.ixx"
        "include/zerossg/third_party/yaml_cpp.ixx"
        "include/zerossg/third_party/openssl.ixx"
)

# Add implementation files (.cpp)
target_sources(zerossg_lib
    PRIVATE
        "src/config/config_manager.cpp"
        # "src/cli/cli_interface.cpp"  # Commented out due to m_server dependency issues
        "src/logging/logger.cpp"
        # Add other .cpp files here
)

# 5. COMPILER CONFIGURATION
target_include_directories(zerossg_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_options(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4> # Removed /WX (warnings as errors) for soft build
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_compile_definitions(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

# Flags that should be inherited by library consumers (e.g., tests)
target_compile_options(zerossg_lib PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

# 6. LINKING
target_link_libraries(zerossg_lib 
    PUBLIC 
        Boost::system 
        Boost::thread 
        OpenSSL::SSL 
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        yaml-cpp::yaml-cpp
    PRIVATE
        Threads::Threads
)

if(Readline_FOUND)
    target_link_libraries(zerossg_lib PUBLIC Readline::Readline)
    target_compile_definitions(zerossg_lib PUBLIC HAS_READLINE)
endif()

# 7. EXECUTABLE
add_executable(zerossg_app 
    "src/main.cpp"
    "src/network/gateway_server.cpp"
    "src/tls/tls_handler.cpp"
)
target_link_libraries(zerossg_app 
    PRIVATE zerossg_lib
    Boost::date_time
    Boost::container
    yaml-cpp
)

# 8. TESTS (enabled)
enable_testing()

include(FetchContent)
FetchContent_Declare(
    ut
    GIT_REPOSITORY https://github.com/boost-ext/ut
    GIT_TAG        v1.1.9
)
FetchContent_MakeAvailable(ut)

add_executable(zerossg_tests 
    "tests/test_authentication.cpp"
    "tests/test_authorization.cpp"
    "tests/test_session_manager.cpp"
    "tests/test_logger.cpp"
    "tests/test_web_server.cpp"
    src/auth/authenticator.cpp
    src/rbac/authorizer.cpp
    src/session/session_manager.cpp
    src/logging/logger.cpp
)
target_link_libraries(zerossg_tests 
    PRIVATE zerossg_lib
    Boost::date_time
    Boost::container
    yaml-cpp
    ut::ut
)
target_include_directories(zerossg_tests PRIVATE ${ut_SOURCE_DIR}/include)

add_test(NAME AllTests COMMAND zerossg_tests)

# Web interface executable
add_executable(zerossg_web src/web_main.cpp)
target_link_libraries(zerossg_web PRIVATE zerossg_lib)
target_sources(zerossg_web PRIVATE 
    src/web/web_server_impl.cpp
)

# Add WinSock library for Windows port checking
if(WIN32)
    target_link_libraries(zerossg_web PRIVATE ws2_32)
endif()

# Set module properties for web server
set_source_files_properties(src/web/web_server_impl.cpp PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
)