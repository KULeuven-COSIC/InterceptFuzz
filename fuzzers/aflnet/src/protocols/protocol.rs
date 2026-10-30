use std::fmt::Debug;

pub const STATE_INITIAL: u32 = 0x10000000;
pub const STATE_ERROR: u32 = 0xFFFFFFFF;

/// A trait that defines how a specific protocol extracts and filters its states.
pub trait Protocol {
    type State: Debug;

    /// Dissect the packet slice and return the Protocol's specific State type
    fn type_to_state(packet_type: u8) -> Self::State;

    /// Decide whether to keep this state in the FSM (e.g., ignore errors/ACKs)
    fn should_keep(state: &Self::State) -> bool;

    fn get_max_packet_size() -> u32;
}

/// The single, unified outbox parser.
/// It uses `<P: Protocol>` to magically adapt to whatever protocol you want!
pub fn extract_states_from_outbox<P: Protocol>(
    outbox_ptr: *mut u8,
    ignore_direction: bool,
) -> Vec<P::State> {
    let mut states = Vec::new();

    unsafe {
        const MAX_CAPACITY: usize = 1024 * 1024 - 4;
        let raw_total = *(outbox_ptr as *const u32) as usize;
        let total_bytes = std::cmp::min(raw_total, MAX_CAPACITY);
        let mut cursor = 4;

        while cursor < 4 + total_bytes {
            // Read the 6-byte header: [1b Dir] [1b Type] [4b Len BE]
            let direction = *outbox_ptr.add(cursor);
            let packet_type = *outbox_ptr.add(cursor + 1);

            let len_b0 = *outbox_ptr.add(cursor + 2) as usize;
            let len_b1 = *outbox_ptr.add(cursor + 3) as usize;
            let len_b2 = *outbox_ptr.add(cursor + 4) as usize;
            let len_b3 = *outbox_ptr.add(cursor + 5) as usize;
            let packet_len = (len_b0 << 24) | (len_b1 << 16) | (len_b2 << 8) | len_b3;

            if cursor + 6 + packet_len > 4 + total_bytes {
                break;
            }
            cursor += 6;

            if direction == 0x01 || ignore_direction {
                let state = P::type_to_state(packet_type);

                if P::should_keep(&state) {
                    states.push(state);
                }
            }

            cursor += packet_len;
        }
    }

    states
}
