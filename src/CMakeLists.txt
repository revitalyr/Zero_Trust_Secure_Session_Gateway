# Source CMakeLists.txt

# Collect source files from all modules
file(GLOB_RECURSE NETWORK_SOURCES "network/*.cpp")
file(GLOB_RECURSE TLS_SOURCES "tls/*.cpp")
file(GLOB_RECURSE AUTH_SOURCES "auth/*.cpp")
file(GLOB_RECURSE RBAC_SOURCES "rbac/*.cpp")
file(GLOB_RECURSE SESSION_SOURCES "session/*.cpp")
file(GLOB_RECURSE PROXY_SOURCES "proxy/*.cpp")
file(GLOB_RECURSE SECURITY_SOURCES "security/*.cpp")
file(GLOB_RECURSE LOGGING_SOURCES "logging/*.cpp")
file(GLOB_RECURSE CONFIG_SOURCES "config/*.cpp")
file(GLOB_RECURSE CLI_SOURCES "cli/*.cpp")

# Main executable source
set(MAIN_SOURCES "main.cpp")

# Create executable
add_executable(zerossg_gateway
    ${MAIN_SOURCES}
    ${NETWORK_SOURCES}
    ${TLS_SOURCES}
    ${AUTH_SOURCES}
    ${RBAC_SOURCES}
    ${SESSION_SOURCES}
    ${PROXY_SOURCES}
    ${SECURITY_SOURCES}
    ${LOGGING_SOURCES}
    ${CONFIG_SOURCES}
    ${CLI_SOURCES}
)

# Link libraries
target_link_libraries(zerossg_gateway
    Boost::system
    ${OPENSSL_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    ${NLOHMANN_JSON_LIBRARIES}
    ${YAML_CPP_LIBRARIES}
)

# Link against interface libraries for C++23 modules (only if CMake version supports modules)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.28")
    target_link_libraries(zerossg_gateway
        zerossg.std
        zerossg.common
        zerossg.types
        zerossg.interfaces
        zerossg.auth.authenticator
        zerossg.logging.logger
        zerossg.session.session_manager
    )
endif()

# Windows specific libraries
if(WIN32)
    target_link_libraries(zerossg_gateway ws2_32 wsock32)
endif()

# Set output directory
set_target_properties(zerossg_gateway PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
