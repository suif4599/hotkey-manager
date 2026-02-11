cmake_minimum_required(VERSION 3.10)
project(NotificationOSD CXX)

set(CMAKE_C_STANDARD 99)

# 使用 PkgConfig 查找 dbus-1
find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)

include_directories(${DBUS_INCLUDE_DIRS})
add_definitions(${DBUS_CFLAGS_OTHER})

add_executable(osd_tool test.cpp)
target_link_libraries(osd_tool ${DBUS_LIBRARIES})