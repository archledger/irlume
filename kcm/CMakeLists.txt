# SPDX-FileCopyrightText: 2026 Wisbendji Fimerlus <archledger236@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.16)
project(irlume-kcm LANGUAGES CXX)

set(QT_MIN_VERSION "6.5.0")
# 6.2: the Diagnostics section headers set Kirigami's ListSectionHeader
# `text`, which earlier releases do not draw. Kirigami is a runtime QML
# dependency with no CMake package here, so this floor is its proxy.
set(KF6_MIN_VERSION "6.2.0")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(ECM ${KF6_MIN_VERSION} REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

find_package(Qt6 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core Gui Quick)
find_package(KF6 ${KF6_MIN_VERSION} REQUIRED COMPONENTS CoreAddons KCMUtils KIO)

add_subdirectory(src)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
