cmake_minimum_required(VERSION 3.20)

# C is needed for the MIG-generated mach_exc exception server used by the loader
# (rosetta_loader build dir mach_excServer.c).
project(rosetta_aot C CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
foreach(cfg IN ITEMS Debug Release RelWithDebInfo MinSizeRel)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

add_subdirectory(rosetta_config)
add_subdirectory(rosetta_core)
add_subdirectory(rosetta_runtime)
add_subdirectory(rosetta_loader)

add_subdirectory(aotinvoke)
add_subdirectory(tests)
add_subdirectory(benchmarks)
