cmake_minimum_required(VERSION 3.20)
project(thirdeye C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_language(ASM)

set(COMMON_COMPILE_OPTIONS
    -fno-stack-protector
    -fno-exceptions
    -fno-rtti
    -fno-toplevel-reorder
)

set(COMMON_LIBS user32 gdi32 gdiplus ole32)

set(CORE_SOURCES
    thirdeye_core.cpp
    syscalls.S
)

set(CORE_HEADERS
    thirdeye_core.h
    internal.h
)

add_library(thirdeye_core STATIC
    ${CORE_SOURCES}
    ${CORE_HEADERS}
)

target_compile_options(thirdeye_core PRIVATE ${COMMON_COMPILE_OPTIONS})
target_include_directories(thirdeye_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(thirdeye_core PUBLIC ${COMMON_LIBS})

add_library(thirdeye_dll SHARED
    dllmain.cpp
    thirdeye.def
)

set_target_properties(thirdeye_dll PROPERTIES
    OUTPUT_NAME "thirdeye"
    PREFIX ""
)

target_compile_definitions(thirdeye_dll PRIVATE THIRDEYE_BUILD_DLL)
target_compile_options(thirdeye_dll PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(thirdeye_dll PRIVATE thirdeye_core)
target_link_options(thirdeye_dll PRIVATE
    -static
    -static-libgcc
    -static-libstdc++
)

add_executable(thirdeye_exe
    main.cpp
)

set_target_properties(thirdeye_exe PROPERTIES
    OUTPUT_NAME "thirdeye"
)

target_compile_options(thirdeye_exe PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(thirdeye_exe PRIVATE thirdeye_core)
target_link_options(thirdeye_exe PRIVATE
    -static
    -static-libgcc
    -static-libstdc++
)

install(TARGETS thirdeye_dll thirdeye_exe
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES thirdeye_core.h DESTINATION include)

add_custom_target(all_targets DEPENDS thirdeye_dll thirdeye_exe)