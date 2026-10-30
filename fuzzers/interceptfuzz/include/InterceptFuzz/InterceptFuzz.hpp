/*
 * InterceptFuzz public API.
 *
 * Integrating InterceptFuzz into a protocol stack takes three things:
 *
 * 1. A test that drives the stack, wrapped as the fuzz harness:
 *
 *        #include <InterceptFuzz/InterceptFuzz.hpp>
 *
 *        INTERCEPTFUZZ_TEST(RunScenario) {
 *            MyIntegrationTest();
 *        }
 *
 * 2. One call where packets enter the stack under test:
 *
 *        len = InterceptFuzz::intercept(buf, len, max_len);             // mutable buffer
 *        auto out = InterceptFuzz::intercept_copy(data, len, max_len);  // immutable packet
 *
 * 3. CMake:
 *
 *        find_package(InterceptFuzz CONFIG REQUIRED)
 *        target_link_libraries(<stack library>  PUBLIC InterceptFuzz::interceptfuzz)
 *        target_link_libraries(<harness binary> PRIVATE InterceptFuzz::harness)
 *
 *    InterceptFuzz::harness adds -fsanitize=fuzzer (the libFuzzer entry point that
 *    AFL++ drives). Compile with afl-clang-lto / afl-clang-fast.
 *
 * At run time the library reads its configuration from the file named by the
 * INTERCEPTFUZZ_CONFIG_PATH environment variable (set by run_interceptfuzz.sh).
 * INTERCEPTFUZZ_VERBOSE=1 prints every intercepted packet before and after.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace InterceptFuzz {

/*
 * Hands an outgoing/incoming packet to the fuzzer, which replays the recorded
 * path to the selected state, injects the fuzzed packet, or records benign
 * traffic, depending on the position in the trace.
 * buf holds len bytes and has room for max_len bytes. Returns the new length.
 */
std::size_t intercept(std::uint8_t* buf, std::size_t len, std::size_t max_len);

/* Same for packets that cannot be modified in place: returns the new bytes. */
std::vector<std::uint8_t> intercept_copy(const std::uint8_t* data, std::size_t len, std::size_t max_len);

/* Used by INTERCEPTFUZZ_TEST. */
int initialize(int* argc, char*** argv);
bool begin_input(const std::uint8_t* data, std::size_t size);

} // namespace InterceptFuzz

/*
 * Defines the libFuzzer entry points. The body runs once per fuzz input,
 * after the input has been handed to the fuzzer.
 */
#define INTERCEPTFUZZ_TEST(name)                                                       \
    static void name();                                                                \
    extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)                       \
    {                                                                                  \
        return ::InterceptFuzz::initialize(argc, argv);                                \
    }                                                                                  \
    extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)  \
    {                                                                                  \
        if (!::InterceptFuzz::begin_input(data, size)) return -1;                      \
        name();                                                                        \
        return 0;                                                                      \
    }                                                                                  \
    static void name()
