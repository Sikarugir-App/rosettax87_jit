
# backwards compatibility with macOS 14 (Sonoma) and later
set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS deployment version")

project(rosetta_loader)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate the MIG mach_exc exception server (message ids 2405-2407,
# MACH_EXCEPTION_CODES) so the loader can receive ptrace debug events on a Mach
# exception port instead of via the deprecated PT_ATTACH/waitpid signal path.
# See src/mach_exception.cpp.
execute_process(
    COMMAND xcrun --sdk macosx --show-sdk-path
    OUTPUT_VARIABLE MACOS_SDK_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(MACH_EXC_SERVER "${CMAKE_CURRENT_BINARY_DIR}/mach_excServer.c")
set(MACH_EXC_SHEADER "${CMAKE_CURRENT_BINARY_DIR}/mach_excServer.h")

add_custom_command(
    OUTPUT ${MACH_EXC_SERVER} ${MACH_EXC_SHEADER}
    COMMAND xcrun mig
            -arch arm64
            -isysroot "${MACOS_SDK_PATH}"
            -server ${MACH_EXC_SERVER}
            -sheader ${MACH_EXC_SHEADER}
            -user /dev/null
            -header /dev/null
            "${MACOS_SDK_PATH}/usr/include/mach/mach_exc.defs"
    DEPENDS "${MACOS_SDK_PATH}/usr/include/mach/mach_exc.defs"
    COMMENT "Generating MIG mach_exc exception server"
    VERBATIM
)

add_executable(runtime_loader
    src/main.cpp
    src/macho_loader.cpp
    src/mach_exception.cpp
    src/offset_finder.cpp
    ${MACH_EXC_SERVER}
)

# mach_exception.cpp includes the generated mach_excServer.h from the build dir.
target_include_directories(runtime_loader PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

set(ENTITLEMENTS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/entitlements.plist")
add_custom_command(TARGET runtime_loader POST_BUILD
    COMMAND codesign -s - --entitlements "${ENTITLEMENTS_FILE}" --force "$<TARGET_FILE:runtime_loader>"
    COMMENT "Signing runtime_loader with entitlements"
)

target_compile_features(runtime_loader PRIVATE cxx_std_23)
target_compile_options(runtime_loader PRIVATE -g)
target_link_libraries(runtime_loader PRIVATE rosetta_config)
