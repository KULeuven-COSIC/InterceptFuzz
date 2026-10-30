cmake_minimum_required(VERSION 3.21)
project(
  InterceptFuzz
  VERSION 0.1.0
  LANGUAGES CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------- The library (link it to the code that calls InterceptFuzz::intercept) ----------
add_library(interceptfuzz src/InterceptFuzz.cpp src/Fuzzer.cpp src/StateDB.cpp)
target_include_directories(
  interceptfuzz PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                       $<INSTALL_INTERFACE:include>)
target_compile_features(interceptfuzz PUBLIC cxx_std_11)
target_compile_definitions(interceptfuzz PRIVATE INTERCEPTFUZZ_BUILD=1)
add_library(InterceptFuzz::interceptfuzz ALIAS interceptfuzz)

# ---------- The harness (link it to the fuzz binary that uses INTERCEPTFUZZ_TEST) ----------
# Adds the libFuzzer entry point that AFL++ drives.
add_library(interceptfuzz_harness INTERFACE)
target_link_libraries(interceptfuzz_harness INTERFACE interceptfuzz)
target_compile_options(interceptfuzz_harness INTERFACE -fsanitize=fuzzer)
target_link_options(interceptfuzz_harness INTERFACE -fsanitize=fuzzer)
set_target_properties(interceptfuzz_harness PROPERTIES EXPORT_NAME harness)
add_library(InterceptFuzz::harness ALIAS interceptfuzz_harness)

# ---------- Install rules ----------
include(CMakePackageConfigHelpers)

install(
  TARGETS interceptfuzz interceptfuzz_harness
  EXPORT InterceptFuzzTargets
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
  INCLUDES
  DESTINATION include)

install(DIRECTORY include/ DESTINATION include)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/InterceptFuzzConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/InterceptFuzzConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/InterceptFuzzConfig.cmake"
  INSTALL_DESTINATION lib/cmake/InterceptFuzz)

install(
  EXPORT InterceptFuzzTargets
  NAMESPACE InterceptFuzz::
  DESTINATION lib/cmake/InterceptFuzz)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/InterceptFuzzConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/InterceptFuzzConfigVersion.cmake"
        DESTINATION lib/cmake/InterceptFuzz)
