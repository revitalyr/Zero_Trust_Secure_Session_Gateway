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
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
)

# Include directories
target_include_directories(zerossg_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add tests
add_test(NAME AllTests COMMAND zerossg_tests)
