# Tests CMakeLists.txt

# Use FetchContent for Boost.UT
include(FetchContent)
FetchContent_Declare(
    ut
    GIT_REPOSITORY https://github.com/boost-ext/ut
    GIT_TAG        v1.1.9
)
FetchContent_MakeAvailable(ut)

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
    ut
    zerossg_lib)

# Include directories
target_include_directories(zerossg_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Add tests
add_test(NAME AllTests COMMAND zerossg_tests)
