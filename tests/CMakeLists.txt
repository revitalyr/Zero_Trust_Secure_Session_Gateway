# Tests CMakeLists.txt

# Find Google Test
find_package(GTest REQUIRED)

# Collect test files
set(TEST_SOURCES
    "test_authentication.cpp"
    "test_authorization.cpp"
    "test_session_manager.cpp"
)

# Create test executable
add_executable(zerossg_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(zerossg_tests
    PRIVATE
    GTest::gtest
    GTest::gtest_main
    zerossg_lib)

# Include directories
target_include_directories(zerossg_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add tests
add_test(NAME AllTests COMMAND zerossg_tests)
