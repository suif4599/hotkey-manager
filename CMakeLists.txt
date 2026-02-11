cmake_minimum_required(VERSION 3.15)
project(hotkey-manager)


# Options
## Python Module
option(BUILD_PYTHON_MODULE "Build Python bindings for hotkey-manager" OFF)
option(PYTHON_EXECUTABLE "Specify the Python executable for bindings" "")
## Daemon Service
option(ENABLE_DAEMON "Enable building hotkey-manager-daemon service" ON)
option(START_DAEMON "Enable and start hotkey-manager-daemon service after installation" ON)
## Grab Device
option(GRAB_DEVICE "Have the daemon grab the input device to prevent other processes from receiving events" ON)
## DUMPABLE
option(ALLOW_DUMP "Allow the daemon to be dumpable for debugging purposes" OFF)


# Condition Check
## Check if ALLOW_DUMP is set on debug builds
if(ALLOW_DUMP)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(FATAL_ERROR "ALLOW_DUMP can only be enabled for Debug builds.")
    endif()
endif()
## Check if running on Linux
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project can only be built on Linux.")
endif()
## Check if the init deamon is systemd
execute_process(
    COMMAND pidof systemd
    RESULT_VARIABLE _systemd_check_status
    OUTPUT_QUIET
    ERROR_QUIET
)
if(NOT _systemd_check_status EQUAL "0")
    message(FATAL_ERROR "This project requires systemd as the init daemon.")
endif()
## Check if libevdev, libsodium and libdbus-1 are installed
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVDEV libevdev)
if(NOT LIBEVDEV_FOUND)
    message(FATAL_ERROR "libevdev library not found. Please install libevdev development packages.")
endif()
pkg_check_modules(LIBSODIUM libsodium)
if(NOT LIBSODIUM_FOUND)
    message(FATAL_ERROR "libsodium library not found. Please install libsodium development packages.")
endif()
pkg_check_modules(DBUS REQUIRED dbus-1)
if(NOT DBUS_FOUND)
    message(FATAL_ERROR "libdbus-1 library not found. Please install libdbus-1 development packages.")
endif()
## Check if gzip and manpath exists for manual page installation
find_program(GZIP_EXECUTABLE gzip)
set(INSTALL_MANPAGES OFF)
if(NOT GZIP_EXECUTABLE)
    message(WARNING "gzip not found. Manual pages will not be installed.")
else()
    find_program(MANPATH_EXECUTABLE manpath)
    if(NOT MANPATH_EXECUTABLE)
        message(WARNING "manpath not found. Manual pages will not be installed.")
    else()
        execute_process(
            COMMAND ${MANPATH_EXECUTABLE}
            RESULT_VARIABLE _manpath_status
            OUTPUT_VARIABLE _manpath_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT _manpath_status EQUAL "0" OR _manpath_output STREQUAL "")
            message(WARNING "Failed to detect manual path. Manual pages will not be installed.")
        else()
            string(REPLACE ":" ";" _manpath_list "${_manpath_output}")
            set(MANPAGE_ROOT_DIR "")
            set(_preferred_man_roots "/usr/local/share/man" "/usr/share/man")
            foreach(_preferred IN LISTS _preferred_man_roots)
                foreach(_candidate IN LISTS _manpath_list)
                    if(EXISTS "${_candidate}" AND "${_candidate}" STREQUAL "${_preferred}")
                        set(MANPAGE_ROOT_DIR "${_candidate}")
                        break()
                    endif()
                endforeach()
                if(NOT MANPAGE_ROOT_DIR STREQUAL "")
                    break()
                endif()
            endforeach()
            if(MANPAGE_ROOT_DIR STREQUAL "")
                foreach(_candidate IN LISTS _manpath_list)
                    if(EXISTS "${_candidate}")
                        set(MANPAGE_ROOT_DIR "${_candidate}")
                        break()
                    endif()
                endforeach()
            endif()
            if(MANPAGE_ROOT_DIR STREQUAL "")
                message(WARNING "No valid manual path found. Manual pages will not be installed.")
            else()
                set(INSTALL_MANPAGES ON)
                message(STATUS "Manual pages will be installed under ${MANPAGE_ROOT_DIR}")
            endif()
        endif()
    endif()
endif()

# Bash completion
set(BASH_COMPLETION_DIR "")
set(_bash_completion_candidates
    "/etc/bash_completion.d"
    "/usr/local/etc/bash_completion.d"
)
foreach(_candidate IN LISTS _bash_completion_candidates)
    if(EXISTS "${_candidate}")
        set(BASH_COMPLETION_DIR "${_candidate}")
        break()
    endif()
endforeach()
if(BASH_COMPLETION_DIR STREQUAL "")
    message(STATUS "bash_completion.d directory not found; bash completion will not be installed.")
else()
    message(STATUS "Bash completion will be installed to ${BASH_COMPLETION_DIR}")
endif()


# Source files
FILE(GLOB DEAMON_SOURCES "daemon/*.cpp")
FILE(GLOB IPC_SOURCES "ipc/*.cpp")
FILE(GLOB CLIENT_SOURCES "client/*.cpp")
FILE(GLOB PYTHON_SOURCES "python/*.cpp")


# Global Configurations
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include(GNUInstallDirs)
set(HOTKEY_MANAGER_CONFIG_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/hotkey-manager-config.json")
set(SYSTEMD_UNIT_INSTALL_DIR "/etc/systemd/system")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    @ONLY
)
include_directories(${CMAKE_CURRENT_BINARY_DIR})


# Targets
## Daemon
add_executable(hotkey-manager-daemon ${DEAMON_SOURCES} ${IPC_SOURCES})
target_include_directories(hotkey-manager-daemon PRIVATE ${LIBEVDEV_INCLUDE_DIRS})
target_include_directories(hotkey-manager-daemon PRIVATE ${LIBSODIUM_INCLUDE_DIRS})
target_include_directories(hotkey-manager-daemon PRIVATE ${DBUS_INCLUDE_DIRS})
target_link_libraries(hotkey-manager-daemon PRIVATE ${LIBEVDEV_LIBRARIES})
target_link_libraries(hotkey-manager-daemon PRIVATE ${LIBSODIUM_LIBRARIES})
target_link_libraries(hotkey-manager-daemon PRIVATE ${DBUS_LIBRARIES})
if(GRAB_DEVICE)
    target_compile_definitions(hotkey-manager-daemon PRIVATE ENABLE_GRAB_DEVICE)
endif()
## Library
add_library(hotkey-manager-client SHARED ${CLIENT_SOURCES} ${IPC_SOURCES})
target_include_directories(hotkey-manager-client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${LIBSODIUM_INCLUDE_DIRS}
)
target_link_libraries(hotkey-manager-client PRIVATE ${LIBSODIUM_LIBRARIES})
set_target_properties(hotkey-manager-client PROPERTIES
    PUBLIC_HEADER client/interface.h
)
if(ALLOW_DUMP)
    target_compile_definitions(hotkey-manager-client PRIVATE ALLOW_DUMP)
endif()
## Python Module
if(BUILD_PYTHON_MODULE)
    # Find Python
    if(PYTHON_EXECUTABLE)
        if(PYTHON_VERSION)
            message(FATAL_ERROR "PYTHON_EXECUTABLE and PYTHON_VERSION cannot be set at the same time.")
        endif()
        set(Python_EXECUTABLE "${PYTHON_EXECUTABLE}")
        execute_process(
            COMMAND "${PYTHON_EXECUTABLE}" "-c" 
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
            RESULT_VARIABLE _python_exec_status
            OUTPUT_VARIABLE PYTHON_VERSION_MICRO
            ERROR_STRIP_TRAILING_WHITESPACE
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if (NOT _python_exec_status EQUAL "0")
            message(FATAL_ERROR "Failed to get Python version using ${PYTHON_EXECUTABLE}.")
        endif()
        find_package(Python ${PYTHON_VERSION_MICRO} EXACT REQUIRED COMPONENTS Interpreter Development)
    else()
        find_package(Python REQUIRED COMPONENTS Interpreter Development)
    endif()
    # Compile the Python module
    add_library(hotkey-manager-python MODULE ${IPC_SOURCES} ${CLIENT_SOURCES} ${PYTHON_SOURCES})
    set_target_properties(hotkey-manager-python PROPERTIES
        PREFIX ""
        SUFFIX ".abi3.so"
        OUTPUT_NAME "hotkey_manager"
    )
    target_include_directories(hotkey-manager-python PRIVATE ${Python_INCLUDE_DIRS})
    target_link_libraries(hotkey-manager-python PRIVATE ${LIBSODIUM_LIBRARIES})
    target_link_libraries(hotkey-manager-python PRIVATE ${Python_LIBRARIES})
    target_compile_definitions(hotkey-manager-python PRIVATE)
    if (ALLOW_DUMP)
        target_compile_definitions(hotkey-manager-python PRIVATE ALLOW_DUMP)
    endif()
    ## Must statically link libstdc++
    target_link_libraries(hotkey-manager-python PRIVATE -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic)
    # Build python module structure
    ## Project Structure:
    ### hotkey-manager/
    ### ├── src/
    ### │   └── hotkey_manager/
    ### │       ├── __init__.py
    ### │       ├── hotkey_manager.abi3.so
    ### │       └── hotkey_manager.pyi
    ### ├── pyproject.toml
    ### ├── README.md
    ### └── LICENSE
    ## Source files
    set(PYTHON_PACKAGE_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/python_package/hotkey_manager")
    set(PYTHON_PACKAGE_SRC_DIR "${PYTHON_PACKAGE_OUTPUT_DIR}/src/hotkey_manager")
    add_custom_command(TARGET hotkey-manager-python POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${PYTHON_PACKAGE_OUTPUT_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${PYTHON_PACKAGE_SRC_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:hotkey-manager-python>
            "${PYTHON_PACKAGE_SRC_DIR}/hotkey_manager.abi3.so"
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/python/hotkey_manager.pyi"
        "${PYTHON_PACKAGE_SRC_DIR}/hotkey_manager.pyi"
        COPYONLY
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/python/__init__.py"
        "${PYTHON_PACKAGE_SRC_DIR}/__init__.py"
        COPYONLY
    )
    ## pyproject.toml
    execute_process(
        COMMAND "${Python_EXECUTABLE}" "-c"
        "import sysconfig; print(sysconfig.get_platform())"
        RESULT_VARIABLE _python_exec_status
        OUTPUT_VARIABLE PYTHON_PLATFORM_TAG
        ERROR_STRIP_TRAILING_WHITESPACE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT _python_exec_status EQUAL "0")
        message(FATAL_ERROR "Failed to get Python platform tag using ${Python_EXECUTABLE}.")
    endif()
    string(TOLOWER "${PYTHON_PLATFORM_TAG}" _python_platform_tag_lower)
    if (NOT _python_platform_tag_lower MATCHES "linux")
        message(FATAL_ERROR "hotkey-manager Python bindings require a Linux Python environment.")
    endif()
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/python/pyproject.toml.in"
        "${PYTHON_PACKAGE_OUTPUT_DIR}/pyproject.toml"
        @ONLY
    )
    ## README and LICENSE
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
        "${PYTHON_PACKAGE_OUTPUT_DIR}/README.md"
        COPYONLY
    )
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
        "${PYTHON_PACKAGE_OUTPUT_DIR}/LICENSE"
        COPYONLY
    )
    # Build wheel inside an isolated virtual environment to avoid touching user or root site-packages
    add_custom_command(TARGET hotkey-manager-python POST_BUILD
        COMMAND ${Python_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/python/build_wheel.py"
            --package-dir "${PYTHON_PACKAGE_OUTPUT_DIR}"
            --wheel-dir "${CMAKE_CURRENT_BINARY_DIR}"
            --venv-dir "${CMAKE_CURRENT_BINARY_DIR}/python_build_env"
    )
endif()

# Manual pages
if(INSTALL_MANPAGES)
    set(MANPAGE_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/man")
    file(MAKE_DIRECTORY "${MANPAGE_BUILD_DIR}")
    set(_MANPAGE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/man/hotkey_manager.3.in"
        "${CMAKE_CURRENT_SOURCE_DIR}/man/hotkey-manager-daemon.1.in"
    )
    set(MANPAGE_OUTPUTS)
    foreach(_manpage IN LISTS _MANPAGE_SOURCES)
        get_filename_component(_manpage_name "${_manpage}" NAME)
        string(REGEX REPLACE "\\.in$" "" _configured_name "${_manpage_name}")
        set(_configured_path "${MANPAGE_BUILD_DIR}/${_configured_name}")
        configure_file("${_manpage}" "${_configured_path}" @ONLY)
        add_custom_command(
            OUTPUT "${_configured_path}.gz"
            COMMAND ${GZIP_EXECUTABLE} -f -k "${_configured_path}"
            DEPENDS "${_configured_path}"
            COMMENT "Compressing ${_configured_name} manual"
            VERBATIM
        )
        list(APPEND MANPAGE_OUTPUTS "${_configured_path}.gz")
    endforeach()
    add_custom_target(manpages ALL DEPENDS ${MANPAGE_OUTPUTS})
endif()


# Install Targets
## Daemon (System Service)
### Stop service if running
install(CODE "message(\"Stopping hotkey-manager-daemon service (if running)...\")")
install(CODE "execute_process(COMMAND systemctl stop hotkey-manager-daemon.service OUTPUT_QUIET ERROR_QUIET)")
### Install executable and service file
install(TARGETS hotkey-manager-daemon
    RUNTIME DESTINATION bin
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/daemon/hotkey-manager-daemon.service.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hotkey-manager-daemon.service"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/hotkey-manager-daemon.service"
    DESTINATION ${SYSTEMD_UNIT_INSTALL_DIR}
)
### Enable service
if (ENABLE_DAEMON OR START_DAEMON)
    install(CODE "message(\"Enabling hotkey-manager-daemon service...\")")
    install(CODE "execute_process(COMMAND systemctl daemon-reload)")
    install(CODE "execute_process(COMMAND systemctl enable hotkey-manager-daemon.service)")
endif()
if (START_DAEMON)
    install(CODE "message(\"Starting hotkey-manager-daemon service...\")")
    install(CODE "execute_process(COMMAND systemctl start hotkey-manager-daemon.service)")
endif()
## Client Library
install(TARGETS hotkey-manager-client
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include/hotkey_manager
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ipc/
    DESTINATION include/hotkey_manager/ipc
    FILES_MATCHING PATTERN "*.h"
)
### Refresh the shared library cache
install(CODE "execute_process(COMMAND ldconfig)")
## Manual Pages
if(INSTALL_MANPAGES)
    install(FILES "${MANPAGE_BUILD_DIR}/hotkey-manager-daemon.1.gz"
        DESTINATION "${MANPAGE_ROOT_DIR}/man1"
    )
    install(FILES "${MANPAGE_BUILD_DIR}/hotkey_manager.3.gz"
        DESTINATION "${MANPAGE_ROOT_DIR}/man3"
    )
endif()
## Bash completion
if(NOT BASH_COMPLETION_DIR STREQUAL "")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/completions/hotkey-manager-daemon.bash"
        DESTINATION "${BASH_COMPLETION_DIR}"
        RENAME "hotkey-manager-daemon"
    )
endif()


# Uninstall Target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/Uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake"
        IMMEDIATE @ONLY)
    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake)
endif()
