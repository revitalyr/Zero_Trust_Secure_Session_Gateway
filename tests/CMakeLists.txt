# Tests CMakeLists.txt

# Find Google Test
find_package(GTest REQUIRED)

# Collect test files
file(GLOB_RECURSE TEST_SOURCES "*.cpp")

# Create test executable
add_executable(zerossg_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(zerossg_tests
    GTest::gtest
    GTest::gtest_main
    Boost::system
    ${OPENSSL_LIBRARIES}
    ${SPDLOG_LIBRARIES}
    ${NLOHMANN_JSON_LIBRARIES}
    ${YAML_CPP_LIBRARIES}
)

# Link against interface libraries for C++23 modules (only if CMake version supports modules)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.28")
    target_link_libraries(zerossg_tests
        zerossg.std
        zerossg.common
        zerossg.types
        zerossg.interfaces
        zerossg.auth.authenticator
        zerossg.logging.logger
        zerossg.session.session_manager
    )
endif()

# Include directories
target_include_directories(zerossg_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add tests
add_test(NAME AllTests COMMAND zerossg_tests)
