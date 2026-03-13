# Source CMakeLists.txt

# Main executable source
set(MAIN_SOURCES "main.cpp")

# Create executable
add_executable(zerossg_gateway ${MAIN_SOURCES})

# Link libraries
target_link_libraries(zerossg_gateway PRIVATE zerossg_lib)

# Windows specific libraries
if(WIN32)
    target_link_libraries(zerossg_gateway PRIVATE ws2_32 wsock32)
endif()

# Set output directory
set_target_properties(zerossg_gateway PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
