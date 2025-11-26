## Demo executable for the client API. The shared library must be built beforehand.
cmake_minimum_required(VERSION 3.15)
project(hotkey-manager-client-demo)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project can only be built on Linux.")
endif()

add_executable(demo client.cpp)
target_link_libraries(demo PRIVATE hotkey-manager-client)
