#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <vector>

using Packet = std::vector<uint8_t>;
using StateID = std::uint32_t;

#define DUMMY_STATE_ID 0

// A helper to print packets for debugging
void print_packet(const Packet& p);

struct Transition {
    StateID from_state;
    Packet packet;
    StateID to_state;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(
        Transition,
        from_state,
        packet,
        to_state
    )
};


class StateDB {
private:
    StateID state_counter_ = 1; // The initial state is always there and has ID=1. ID=0 is considered dummy.
    StateID current_state_ = 1;

    std::vector<Transition> transitions;

public:
    std::vector<Packet> get_path_to(StateID target_id) const;

    // Returns true if the packet is new.
    bool process_packet(const Packet& packet);
    bool process_packet(const uint8_t* data, std::size_t len);
    
    StateID is_known_packet_in_cur_state(const Packet& p);
    StateID is_known_packet_in_cur_state(const uint8_t* data, std::size_t len);

    void jump_to_state(StateID state_id);

    StateID get_current_state() const;

    StateID get_state_count() const;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(
        StateDB,
        state_counter_,
        transitions
    )
};