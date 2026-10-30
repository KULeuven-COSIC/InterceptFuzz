#pragma once

#include "FuzzConfig.hpp"
#include "StateDB.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace InterceptFuzz {

/* The fuzzer state behind the public API in InterceptFuzz.hpp. */
class Fuzzer {
public:
    static bool Init(const std::string& config_file_path) noexcept;
    static Fuzzer& Instance();

    /* Returns the new length of the buffer. */
    std::size_t process(std::uint8_t* buf, std::size_t buf_len, std::size_t buf_max_len) noexcept;

    bool reset_fuzzed_packet(std::uint8_t* buf, std::size_t len) noexcept;

    // No copying/moving
    Fuzzer(const Fuzzer&) = delete;
    Fuzzer& operator=(const Fuzzer&) = delete;
    Fuzzer(Fuzzer&&) = delete;
    Fuzzer& operator=(Fuzzer&&) = delete;

    void disable_fuzzing();
    void enable_fuzzing();

    inline std::size_t get_state_db_size() const {
        return state_db_.get_state_count();
    }

private:
    // Helper functions
    std::size_t replay_recorded_packet(std::uint8_t* buf, std::size_t max_len);
    std::size_t apply_fuzzed_packet(std::uint8_t* buf, std::size_t buf_max_len);
    void handle_benign_traffic(const std::uint8_t* buf, std::size_t len);
    void sync_state_to_disk();
    void save_seed_to_disk(StateID state, const std::uint8_t* buf, std::size_t len);

private:

    Fuzzer() = default;
    static std::unique_ptr<Fuzzer> instance_;

    struct Fuzzed_Packet {
        std::uint8_t* buf;
        std::size_t len;
        std::size_t state;
    } fuzzed_packet_;

    StateID packet_counter_;
    StateID selected_state_id_;
    std::vector<Packet> path_to_selected_state_;

    bool is_fuzzing_enabled = false; // To enable the fuzzing, the user has to set the fuzzed packet.

    static StateDB state_db_;
    static FuzzConfig fuzz_config_;

    bool drop_benign_packets = false;
};

}