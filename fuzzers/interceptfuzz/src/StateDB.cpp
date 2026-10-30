#include "InterceptFuzz/StateDB.hpp"

#include "InterceptFuzz/helpers.hpp"
#include <iostream>

void print_packet(const Packet& p) {
    std::cout << "0x" << std::hex << std::setfill('0');
    for(auto b : p) std::cout << std::setw(2) << (int)b;
    std::cout << std::dec;
}

StateID StateDB::is_known_packet_in_cur_state(const Packet& p) {
    auto it = std::find_if(transitions.begin(), transitions.end(), [&](const Transition& t) {
        return t.from_state == current_state_ && t.packet == p;
    });
    if (it != transitions.end()) return it->to_state;
    return DUMMY_STATE_ID;
}

StateID StateDB::is_known_packet_in_cur_state(const uint8_t* data, std::size_t len) {
    return is_known_packet_in_cur_state(Packet(data, data + len));;
}

bool StateDB::process_packet(const Packet& p) {
    StateID state_id = is_known_packet_in_cur_state(p);
    if (state_id != DUMMY_STATE_ID) {
        // Packet is known
        StateID next = state_id;
        current_state_ = next;
        return false;
    } else {
        // Packet is unknown
        StateID next = ++state_counter_;
        transitions.push_back({current_state_, p, next});
        current_state_ = next;
        return true;
    }
}

bool StateDB::process_packet(const uint8_t* data, std::size_t len) {
    // Construct vector and delegate to the primary implementation
    return process_packet(Packet(data, data + len));
}

// Reconstruct the full packet sequence required to reach target_id
std::vector<Packet> StateDB::get_path_to(StateID target_id) const {
    std::vector<Packet> trace;
    StateID search = target_id;

    // Climb the tree until we hit the root (State with ID=1)
    while (search != 1) {
        auto it = std::find_if(transitions.begin(), transitions.end(), [&](const Transition& t) {
            return t.to_state == search;
        });
        if (it == transitions.end()) break; // Should not happen if ID is valid

        trace.push_back(it->packet);
        search = it->from_state;
    }

    // Trace is built from target to root; reverse for chronological order
    std::reverse(trace.begin(), trace.end());
    return trace;
}

void StateDB::jump_to_state(StateID id) {
    if (id == 0) id = 1; // Jump to the root state if dummy state is requested
    current_state_ = id;
    // std::cout << ">> Jumped to State " << id << "\n";
}

StateID StateDB::get_current_state() const { return current_state_; }

StateID StateDB::get_state_count() const { return state_counter_; }