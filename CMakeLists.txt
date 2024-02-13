cmake_minimum_required(VERSION 3.20)

set(LIB_AAA_ROOT "./lib/Aaa")

add_executable(FileTest
    ${CMAKE_SOURCE_DIR}/AceCondition.cpp
    ${CMAKE_SOURCE_DIR}/AceResource.cpp
    ${CMAKE_SOURCE_DIR}/DateTime.cpp
    ${CMAKE_SOURCE_DIR}/DlgCopyFile.cpp
    ${CMAKE_SOURCE_DIR}/DlgDataEditor.cpp
    ${CMAKE_SOURCE_DIR}/DlgEaEditor.cpp
    ${CMAKE_SOURCE_DIR}/DlgEasEditor.cpp
    ${CMAKE_SOURCE_DIR}/DlgFileTest.cpp
    ${CMAKE_SOURCE_DIR}/DlgFlags.cpp
    ${CMAKE_SOURCE_DIR}/DlgPrivileges.cpp
    ${CMAKE_SOURCE_DIR}/DlgSimple.cpp
    ${CMAKE_SOURCE_DIR}/NtStatus2Text.cpp
    ${CMAKE_SOURCE_DIR}/Page00Transaction.cpp
    ${CMAKE_SOURCE_DIR}/Page01Create.cpp
    ${CMAKE_SOURCE_DIR}/Page02NtCreate.cpp
    ${CMAKE_SOURCE_DIR}/Page03ReadWrite.cpp
    ${CMAKE_SOURCE_DIR}/Page04Mapping.cpp
    ${CMAKE_SOURCE_DIR}/Page05FileOps.cpp
    ${CMAKE_SOURCE_DIR}/Page06NtFileInfo.cpp
    ${CMAKE_SOURCE_DIR}/Page07NtFsInfo.cpp
    ${CMAKE_SOURCE_DIR}/Page08Ea.cpp
    ${CMAKE_SOURCE_DIR}/Page09Security.cpp
    ${CMAKE_SOURCE_DIR}/Page10Links.cpp
    ${CMAKE_SOURCE_DIR}/Page11Streams.cpp
    ${CMAKE_SOURCE_DIR}/Page12Ioctl.cpp
    ${CMAKE_SOURCE_DIR}/ReparseDataHsm.cpp
    ${CMAKE_SOURCE_DIR}/TestCode.cpp
    ${CMAKE_SOURCE_DIR}/TAceHelper.cpp
    ${CMAKE_SOURCE_DIR}/TDataEditor.cpp
    ${CMAKE_SOURCE_DIR}/TToolTip.cpp
    ${CMAKE_SOURCE_DIR}/Utils.cpp
    ${CMAKE_SOURCE_DIR}/WinMain.cpp
    ${CMAKE_SOURCE_DIR}/FileTest.rc
)
add_definitions(-D_AFXDLL)
set(CMAKE_MFC_FLAG 2)

target_link_options(FileTest PRIVATE "/SUBSYSTEM:WINDOWS")

target_include_directories(FileTest PRIVATE "${LIB_AAA_ROOT}/inc")
target_compile_definitions(FileTest PUBLIC WDK_BUILD PUBLIC _DEBUG)
target_compile_options(FileTest PUBLIC /Zc:wchar_t-)

message(CMAKE_GENERATOR_PLATFORM="${CMAKE_GENERATOR_PLATFORM}")

if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
    set(LIB_AAA_VER "lib32")
elseif (CMAKE_GENERATOR_PLATFORM STREQUAL "Win64")
    set(LIB_AAA_VER "lib64")
else()
    message(FATAL_ERROR "Cannot identify is it 32 or 64 bit")
endif()

target_link_libraries(FileTest PRIVATE kernel32.lib shell32.lib Comctl32.lib
    Comdlg32.lib Version.lib ${CMAKE_SOURCE_DIR}/${LIB_AAA_ROOT}/${LIB_AAA_VER}/ntdll.lib
    ${CMAKE_SOURCE_DIR}/${LIB_AAA_ROOT}/${LIB_AAA_VER}/UtilsWDK.lib
    )

project(FileTest)
