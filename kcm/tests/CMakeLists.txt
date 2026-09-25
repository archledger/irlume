# SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Offscreen tests for the module. Built with BUILD_TESTING, which
# KDECMakeSettings turns on by default, so the packaging lanes build them
# too; they need only the module's own build dependencies. Nothing here is
# installed, and .github/workflows/kcm.yml runs each one explicitly.
find_package(Qt6 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core Gui Qml Quick Widgets)

# The bridge's failure paths, against fake irlume programs.
add_executable(kcm_bridgetest bridgetest.cpp ../src/irlumebridge.cpp ../src/irlumebridge.h)
target_include_directories(kcm_bridgetest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(kcm_bridgetest PRIVATE Qt6::Core)

# A fixture-backed stand-in for the module, named kcm_irlume like the real
# plugin (the name picks the qrc:/kcm/kcm_irlume/ path the QML loads from)
# but built into a directory of its own. It carries the module's real QML.
add_library(kcm_irlume_standin MODULE standin.cpp standin.h)
set_target_properties(kcm_irlume_standin PROPERTIES
    OUTPUT_NAME kcm_irlume
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/standin")
# For kcm_irlume.json, which the plugin metadata is read from.
target_include_directories(kcm_irlume_standin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(kcm_irlume_standin PRIVATE Qt6::Core Qt6::Qml KF6::CoreAddons KF6::KCMUtilsQuick)
file(GLOB kcm_ui_files CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/*")
qt_add_resources(kcm_irlume_standin kcm_irlume_standin_ui
    PREFIX "/kcm/kcm_irlume"
    BASE "${CMAKE_CURRENT_SOURCE_DIR}/../src/ui"
    FILES ${kcm_ui_files})

# Every page, for every fixture set, at a narrow and a wide size.
add_executable(kcm_pagetest pagetest.cpp)
target_link_libraries(kcm_pagetest PRIVATE
    Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::Widgets
    KF6::CoreAddons KF6::KCMUtilsQuick)
target_compile_definitions(kcm_pagetest PRIVATE
    IRLUME_STANDIN_MODULE="$<TARGET_FILE:kcm_irlume_standin>"
    IRLUME_TEST_HOST="${CMAKE_CURRENT_SOURCE_DIR}/host.qml"
    IRLUME_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
add_dependencies(kcm_pagetest kcm_irlume_standin)
