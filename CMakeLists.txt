cmake_minimum_required(VERSION 3.30)
project(thirdeye)

set(CMAKE_CXX_STANDARD 20)

add_executable(thirdeye main.cpp)

target_compile_options(thirdeye PRIVATE
        -fno-stack-protector
        -fno-exceptions
        -fno-rtti
        -fno-toplevel-reorder
)

target_link_options(thirdeye PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
)

target_link_libraries(thirdeye PRIVATE user32 gdi32 gdiplus)