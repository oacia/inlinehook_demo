cmake_minimum_required(VERSION 3.28)
enable_language(ASM)
project(self_hook C)
set(CMAKE_C_STANDARD 11)

add_library(hook-agent SHARED
        hook-agent.c
        inlinehook_shellcode.asm)
find_library( log-lib log)
target_link_libraries(hook-agent ${log-lib} )

add_executable(hook-server
        hook-server.c)
