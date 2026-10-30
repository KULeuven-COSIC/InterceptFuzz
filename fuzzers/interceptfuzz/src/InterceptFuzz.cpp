#include "InterceptFuzz/InterceptFuzz.hpp"
#include "InterceptFuzz/Fuzzer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

namespace InterceptFuzz {

namespace {

bool verbose()
{
    static const bool enabled = [] {
        const char* v = std::getenv("INTERCEPTFUZZ_VERBOSE");
        return v != nullptr && *v != '\0' && std::strcmp(v, "0") != 0;
    }();
    return enabled;
}

void print_hex(const char* label, const std::uint8_t* buf, std::size_t size)
{
    std::cout << "--- " << label << " (" << size << " bytes) ---\n";
    if (size == 0) {
        std::cout << "(Empty)\n";
        return;
    }
    for (std::size_t i = 0; i < size; i++) {
        std::printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    if (size % 16 != 0) std::cout << "\n";
}

} // namespace

int initialize(int* /*argc*/, char*** /*argv*/)
{
    const char* path = std::getenv("INTERCEPTFUZZ_CONFIG_PATH");
    if (path == nullptr || *path == '\0') {
        std::cerr << "Environment variable INTERCEPTFUZZ_CONFIG_PATH is not set." << std::endl;
        return -1;
    }
    static const std::string config_file_path = path;
    if (!Fuzzer::Init(config_file_path)) {
        std::cerr << "Failed to set the config file: `" << config_file_path << std::endl;
        throw std::runtime_error("Failed to set the config file.");
    }
    std::cout << "Using the config file: `" << config_file_path << "`\n";
    return 0;
}

bool begin_input(const std::uint8_t* data, std::size_t size)
{
    // The fuzzer keeps a pointer to the input; libFuzzer keeps it alive for the run.
    return Fuzzer::Instance().reset_fuzzed_packet(const_cast<std::uint8_t*>(data), size);
}

std::size_t intercept(std::uint8_t* buf, std::size_t len, std::size_t max_len)
{
    if (verbose()) print_hex("Intercepted packet (original)", buf, len);
    std::size_t new_len = Fuzzer::Instance().process(buf, len, max_len);
    if (verbose()) print_hex("Intercepted packet (fuzzer)", buf, new_len);
    return new_len;
}

std::vector<std::uint8_t> intercept_copy(const std::uint8_t* data, std::size_t len, std::size_t max_len)
{
    std::vector<std::uint8_t> buf(max_len, 0);
    std::size_t copy_len = std::min(len, max_len);
    if (copy_len > 0) std::memcpy(buf.data(), data, copy_len);
    buf.resize(intercept(buf.data(), copy_len, max_len));
    return buf;
}

} // namespace InterceptFuzz
