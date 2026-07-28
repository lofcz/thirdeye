cmake_minimum_required(VERSION 3.20)
project(thirdeye C CXX ASM RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT (/MT) so the DLL/exe never depend on msvcp*/vcruntime* DLLs, which
# matches the intent of the MinGW -static* flags. Applied before any target.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
    enable_language(RC)

    # MSVC equivalents of the MinGW concealment flags:
    #  /GS-            no stack-protector cookies            (vs -fno-stack-protector)
    #  /EHs-c-         no exceptions                          (vs -fno-exceptions)
    #  /GR-            no RTTI                                (vs -fno-rtti)
    #  /Gy             function-level linking                 (vs -ffunction-sections)
    #  /Gw             data in COMDATs                        (vs -fdata-sections)
    #  /Zc:threadSafeInit-  no thread-safe static init guards (vs -fno-threadsafe-statics)
    #  /Oi /GL         intrinsics + whole-program opt
    # /Od on the injection stub is already forced by #pragma optimize in-source.
    # There is no MSVC analog for -fno-toplevel-reorder (MSVC preserves source
    # order within a translation unit), so none is needed for the end marker.
    set(COMMON_COMPILE_OPTIONS
        /GS- /EHs-c- /GR- /Gy /Gw /Zc:threadSafeInit- /Oi
        /constexpr:steps20000000
        /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN
    )
    # Strip unreferenced code/data, fold ICF, and drop the .pdb from the DLL.
    # No /DEBUG -> no PDB. No .ld script or post-build patch: the MinGW runtime
    # (winpthreads, "Mingw-w64 runtime failure") does not exist under MSVC.
    set(COMMON_LINK_OPTIONS /OPT:REF /OPT:ICF /INCREMENTAL:NO)
else()
    enable_language(ASM)
    enable_language(RC)

    set(COMMON_COMPILE_OPTIONS
        -fno-stack-protector
        -fno-exceptions
        -fno-rtti
        -fno-toplevel-reorder
        -fno-ident
        -fno-asynchronous-unwind-tables
        -fno-unwind-tables
        -fno-threadsafe-statics
        -ffunction-sections
        -fdata-sections
    )
    set(COMMON_LINK_OPTIONS
        -static
        -static-libgcc
        -static-libstdc++
        -s
        -Wl,--gc-sections
        -Wl,--exclude-all-symbols
        -Wl,--script=${CMAKE_CURRENT_SOURCE_DIR}/strip_toolchain.ld
    )
endif()

# The DLL resolves every USER32 and GDI32 function dynamically (window
# enumeration, capture) from shredded strings, and every GDI+ dependency is
# gone, so neither user32 nor gdi32 is statically linked into the DLL. gdi32
# stays only on the test binaries that call GDI statically.
set(COMMON_LIBS )
set(GDI_LIBS gdi32)
set(USER32_LIBS user32)

set(CORE_SOURCES
    thirdeye_core.cpp
    lge_syscalls.cpp
    dynresolve.cpp
    lodepng.c
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
    version.rc
)

set_target_properties(thirdeye_dll PROPERTIES
    OUTPUT_NAME "thirdeye"
    PREFIX ""
)

target_compile_definitions(thirdeye_dll PRIVATE THIRDEYE_BUILD_DLL)
target_compile_options(thirdeye_dll PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(thirdeye_dll PRIVATE thirdeye_core)

if(NOT MSVC)
    # Freestanding: no MinGW/UCRT startup, atexit, TLS support, or CRT import
    # DLLs. crt_shim supplies the few routines the code uses, on the NT heap.
    target_sources(thirdeye_dll PRIVATE crt_shim.c)
    set_source_files_properties(crt_shim.c PROPERTIES
        COMPILE_OPTIONS "-ffreestanding;-fno-builtin")

    # Encoders keep only their in-memory paths (drop fopen/fread/fwrite).
    target_compile_definitions(thirdeye_core PRIVATE LODEPNG_NO_COMPILE_DISK TJE_NO_FILE_IO)

    target_link_options(thirdeye_dll PRIVATE ${COMMON_LINK_OPTIONS}
        -nostdlib
        -Wl,--entry,DllMain
    )
    # Only kernel32 (HeapAlloc/GetProcessHeap + the benign sync/thread APIs the
    # code calls directly) is linked; nothing else.
    target_link_libraries(thirdeye_dll PRIVATE kernel32)
else()
    target_link_options(thirdeye_dll PRIVATE ${COMMON_LINK_OPTIONS})
endif()

if(NOT MSVC)
    # MinGW-only post-build: rewrites winpthreads/mingw runtime strings in the
    # binary. The MSVC runtime has none of these, so skip under MSVC.
    add_custom_command(TARGET thirdeye_dll POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPATCH_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/patch_toolchain.py -DBINARY=$<TARGET_FILE:thirdeye_dll> -P ${CMAKE_CURRENT_SOURCE_DIR}/run_patch.cmake
    )
endif()

add_executable(thirdeye_exe
    main.cpp
)

set_target_properties(thirdeye_exe PROPERTIES
    OUTPUT_NAME "thirdeye"
)

target_compile_options(thirdeye_exe PRIVATE ${COMMON_COMPILE_OPTIONS})
target_link_libraries(thirdeye_exe PRIVATE thirdeye_core ${USER32_LIBS})
target_link_options(thirdeye_exe PRIVATE ${COMMON_LINK_OPTIONS})

if(NOT MSVC)
    add_custom_command(TARGET thirdeye_exe POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPATCH_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/patch_toolchain.py -DBINARY=$<TARGET_FILE:thirdeye_exe> -P ${CMAKE_CURRENT_SOURCE_DIR}/run_patch.cmake
    )
endif()

install(TARGETS thirdeye_dll thirdeye_exe
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES thirdeye_core.h DESTINATION include)

add_custom_target(all_targets DEPENDS thirdeye_dll thirdeye_exe)

option(THIRDEYE_BUILD_TESTS "Build the thirdeye E2E tests" ON)

if(THIRDEYE_BUILD_TESTS)
    enable_testing()

    add_executable(capture_target WIN32 tests/capture_target.cpp)
    target_link_libraries(capture_target PRIVATE user32 gdi32)
    if(NOT MSVC)
        target_link_options(capture_target PRIVATE -static -static-libgcc -static-libstdc++)
    endif()

    add_executable(e2e_test tests/e2e_test.cpp)
    target_include_directories(e2e_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    # The test harness decodes JPEG via GDI+ to verify markers; that lives only
    # in the test binary, never in the shipped DLL (which stays GDI+ free).
    target_link_libraries(e2e_test PRIVATE thirdeye_core ${COMMON_LIBS} ${USER32_LIBS} ${GDI_LIBS} gdiplus ole32)
    if(NOT MSVC)
        target_link_options(e2e_test PRIVATE -static -static-libgcc -static-libstdc++)
    endif()

    add_test(
        NAME wda_exclude_from_capture
        COMMAND e2e_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(wda_exclude_from_capture PROPERTIES TIMEOUT 60)
endif()