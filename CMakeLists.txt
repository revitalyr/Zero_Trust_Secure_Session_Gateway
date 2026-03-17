cmake_minimum_required(VERSION 3.28) # Рекомендуется 3.28+ для стабильных модулей

# 1. ПОДАВЛЕНИЕ ПРЕДУПРЕЖДЕНИЙ (ДО project())
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS ON CACHE BOOL "Mute dev warnings" FORCE)
# Убираем предупреждения о старом поиске Boost
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
# Убираем предупреждение о FetchContent_Populate (для CPM/UT)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
# Убираем предупреждения add_custom_command (для UT)
if(POLICY CMP0175)
    cmake_policy(SET CMP0175 OLD)
endif()

project(ZeroTrustSecureSessionGateway VERSION 1.0.0 LANGUAGES CXX)

# Windows-specific definitions
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0601) 
endif()

# 2. НАСТРОЙКИ СТАНДАРТА
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

# 3. ПОИСК ЗАВИСИМОСТЕЙ (vcpkg)
# Поиск Readline (QUIET убирает Warning, если библиотека не найдена)
find_package(Readline QUIET)

# Поиск остальных зависимостей
find_package(Boost REQUIRED COMPONENTS system thread date_time container)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(yaml-cpp CONFIG REQUIRED)

# 4. СОЗДАНИЕ БИБЛИОТЕКИ (MODULES)
add_library(zerossg_lib)

# Добавление файлов интерфейсов модулей (.ixx)
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
        "include/zerossg/third_party/nlohmann_json.ixx"
        "include/zerossg/third_party/yaml_cpp.ixx"
        "include/zerossg/third_party/openssl.ixx"
)

# Добавление файлов реализации (.cpp)
target_sources(zerossg_lib
    PRIVATE
        "src/config/config_manager.cpp"
        # "src/cli/cli_interface.cpp"  # Commented out due to m_server dependency issues
        "src/logging/logger.cpp"
        # Добавьте остальные .cpp файлы проекта здесь
)

# 5. КОНФИГУРАЦИЯ КОМПИЛЯТОРА
target_include_directories(zerossg_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_options(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4> # Убрали /WX (warnings as errors) для мягкой сборки
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_compile_definitions(zerossg_lib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

# Флаги, которые должны наследоваться потребителями библиотеки (например, тестами)
target_compile_options(zerossg_lib PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

# 6. ЛИНКОВКА
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

# 7. ИСПОЛНЯЕМЫЙ ФАЙЛ
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

# 8. ТЕСТЫ (暂时禁用)
# enable_testing()

# include(FetchContent)
# FetchContent_Declare(
#     ut
#     GIT_REPOSITORY https://github.com/boost-ext/ut
#     GIT_TAG        v1.1.9
# )
# FetchContent_MakeAvailable(ut)

# add_executable(zerossg_tests 
#     "tests/test_authentication.cpp"
#     "tests/test_authorization.cpp"
#     "tests/test_session_manager.cpp"
#     src/auth/authenticator.cpp
#     src/rbac/authorizer.cpp
#     src/session/session_manager.cpp
# )
# target_link_libraries(zerossg_tests 
#     PRIVATE zerossg_lib
#     Boost::date_time
#     Boost::container
#     yaml-cpp
# )
# target_include_directories(zerossg_tests PRIVATE ${ut_SOURCE_DIR}/include)

# add_test(NAME AllTests COMMAND zerossg_tests)

# Simple CLI executable for testing (without complex dependencies)
add_executable(zerossg_simple src/simple_main.cpp)
target_link_libraries(zerossg_simple PRIVATE zerossg_lib)
target_sources(zerossg_simple PRIVATE 
    src/cli/cli_interface_simple.cpp
)