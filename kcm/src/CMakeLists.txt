# SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# The plugin name IS the target name: kcm_irlume.so, kcm_irlume.json and
# `kcmshell6 kcm_irlume` must all agree, and the desktop-file generator
# requires the JSON basename to match the target.
kcmutils_add_qml_kcm(
    kcm_irlume
    SOURCES
        irlumekcm.cpp
        irlumekcm.h
        irlumebridge.cpp
        irlumebridge.h
)
target_link_libraries(
    kcm_irlume
    PRIVATE
        Qt6::Core
        Qt6::Gui
        KF6::CoreAddons
        KF6::KCMUtilsQuick
        KF6::KIOGui
)

# Headless load test: loads the built plugin (metadata + factory) and
# exercises the bridge against the real CLI. Built only when the caller
# asks for it (BUILD_TESTING) so packaging lanes can skip it; it is never
# installed.
if(BUILD_TESTING)
    find_package(Qt6 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core)
    add_executable(kcm_loadtest ../tests/loadtest.cpp irlumebridge.cpp irlumebridge.h)
    target_include_directories(kcm_loadtest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(
        kcm_loadtest
        PRIVATE
            Qt6::Core
            KF6::CoreAddons
    )
endif()
