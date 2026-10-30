#include "InterceptFuzz/Fuzzer.hpp"

#include "InterceptFuzz/helpers.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace InterceptFuzz {

StateDB Fuzzer::state_db_;
FuzzConfig Fuzzer::fuzz_config_;
std::unique_ptr<Fuzzer> Fuzzer::instance_ = nullptr;

bool Fuzzer::reset_fuzzed_packet(std::uint8_t* buf, std::size_t len) noexcept {
    packet_counter_ = 0U; // Start the packet counter from 1. The 0th state is the dummy state used to skip the fuzzing completely and get a benign trace.
    drop_benign_packets = false;
    /* Fix the seed in RNG. */
    srand(0U);

    if (len < sizeof(StateID)) {
        std::cerr << "The buffer length is too small to contain the state info." << std::endl;
        return false;
    }
    /* Parse seed and state. */
    std::size_t idx = 0;
    std::memcpy(&fuzzed_packet_.state, &buf[idx], sizeof(StateID));
    idx += sizeof(StateID);

    /* Set the buffer and length info. */
    fuzzed_packet_.buf = buf + idx;
    fuzzed_packet_.len = len - idx;

    selected_state_id_ = fuzzed_packet_.state; /* Specified by the fuzzer. */

    if (selected_state_id_ > state_db_.get_state_count()) {
        std::cerr << "The expected state " << selected_state_id_ << " is out of range. Max state is " << state_db_.get_state_count() << std::endl;
        return false;
    }
    path_to_selected_state_ = state_db_.get_path_to(selected_state_id_);
    state_db_.jump_to_state(selected_state_id_);

    is_fuzzing_enabled = true;

    //InjectStateCoverage(selected_state_id_);

    return true;
}

std::size_t Fuzzer::process(std::uint8_t* buf, std::size_t buf_len, std::size_t buf_max_len) noexcept {
    std::size_t new_len = buf_len;

    if (!is_fuzzing_enabled) return new_len;

    if (packet_counter_ < path_to_selected_state_.size()) {
        assert(packet_counter_ > 0);
        new_len = replay_recorded_packet(buf, buf_max_len);
    } else if (packet_counter_ == path_to_selected_state_.size() && selected_state_id_ != 0) {
        new_len = apply_fuzzed_packet(buf, buf_max_len);
    } else {
        if (fuzz_config_.fuzz_mode == FuzzConfig::FuzzMode::FUZZ && drop_benign_packets) {
            //std::memset(buf, 0, buf_len);
            exit(0);
        } else {
            handle_benign_traffic(buf, buf_len);
        }
    }

    packet_counter_++;

    return new_len;
}

std::size_t Fuzzer::replay_recorded_packet(std::uint8_t* buf, std::size_t max_len) {
    const Packet& packet = path_to_selected_state_.at(packet_counter_);
    std::size_t actual_len = std::min(packet.size(), max_len);
    std::memcpy(buf, packet.data(), actual_len);
    return actual_len;
}

std::size_t Fuzzer::apply_fuzzed_packet(std::uint8_t* buf, std::size_t buf_max_len) {
    // 1. Determine safe length and move the fuzzed data into the buffer
    std::size_t actual_len = std::min(fuzzed_packet_.len, buf_max_len);
    std::memcpy(buf, fuzzed_packet_.buf, actual_len);

    if (fuzz_config_.fuzz_mode == FuzzConfig::FuzzMode::SAVE_SEEDS) {
        // Ensure our internal state tracking matches the state we selected to fuzz
        assert(state_db_.get_current_state() == selected_state_id_);
        
        // Feed the fuzzed packet into the DB to transition its internal state
        state_db_.process_packet(fuzzed_packet_.buf, actual_len);

        // Do NOT save the state DB here, as it will be saved after the next benign packet.
        // If there will be no benign packets after this, the state is useless for us.
    } else {
        // FUZZ MODE
        if (state_db_.is_known_packet_in_cur_state(fuzzed_packet_.buf, actual_len) != DUMMY_STATE_ID) {
            // We are at the start of the fuzzing, where AFL replays the initial seeds.
            // To avoid the case, where AFL only saves the first seed, we drop the subsequent benign packets.
            drop_benign_packets = true;
        }
    }

    return actual_len;
}

void Fuzzer::handle_benign_traffic(const std::uint8_t* buf, std::size_t len) {
    if (fuzz_config_.fuzz_mode != FuzzConfig::FuzzMode::SAVE_SEEDS) return;

    StateID current_state = state_db_.get_current_state();
    state_db_.process_packet(buf, len);
    sync_state_to_disk();
    save_seed_to_disk(current_state, buf, len);
}

void Fuzzer::sync_state_to_disk() {
    if (!write_class_instance_to_json_file(state_db_, std::filesystem::path{fuzz_config_.state_db_path})) {
        std::cerr << "Failed to save state db to " << fuzz_config_.state_db_path << "\n";
    }
}

void Fuzzer::save_seed_to_disk(StateID state, const std::uint8_t* buf, std::size_t len) {
    // Use a vector to handle memory automatically (RAII)
    std::vector<std::uint8_t> seed_data(sizeof(StateID) + len);
    std::memcpy(seed_data.data(), &state, sizeof(StateID));
    std::memcpy(seed_data.data() + sizeof(StateID), buf, len);

    auto path = std::filesystem::path(fuzz_config_.seeds_path) / ("seed_" + std::to_string(state));
    if (!write_buffer_to_file(seed_data.data(), seed_data.size(), path)) {
        std::cerr << "Failed to save seed for state: " << state << "\n";
    }
}

Fuzzer& Fuzzer::Instance() {
    if (!instance_) {
        throw std::logic_error("Fuzzer not initialized. Call Fuzzer::Init... in main first.");
    }
    return *instance_;
}

bool Fuzzer::Init(const std::string& config_path) noexcept {
    std::cout << "Initializing the fuzzer" << std::endl;
    std::filesystem::path f_path{config_path};
    if (!parse_json_file_into_class_instance(f_path, fuzz_config_)) return false;
    try {
        instance_.reset(new Fuzzer());
    } catch (std::runtime_error& ex) {
        std::cerr << "Failed to init the fuzzer: " << ex.what() << std::endl;
        return false;
    }

    /* Initialization for different configurations. */
    if (fuzz_config_.fuzz_mode == FuzzConfig::FuzzMode::SAVE_SEEDS) {
        /* Create a directory for the seeds */
        if (!create_directories_if_not_exist(fuzz_config_.seeds_path)) {
            return false;
        }
    }

    if (check_if_path_exists(std::filesystem::path{fuzz_config_.state_db_path})) {
        if (!parse_json_file_into_class_instance(std::filesystem::path{fuzz_config_.state_db_path}, state_db_)) {
            std::cerr << "Failed to load the state db from " << fuzz_config_.state_db_path << std::endl;
            return false;
        }
        std::cout << "Loaded the state db from " << fuzz_config_.state_db_path << std::endl;
    } else {
        std::cout << "The state db file does not exist: " << fuzz_config_.state_db_path << std::endl;
        std::cout << "Using default values." << std::endl;
    }
    
    return true;
}

void Fuzzer::disable_fuzzing() {
    is_fuzzing_enabled = false;
}

void Fuzzer::enable_fuzzing() {
    is_fuzzing_enabled = true;
}

}
