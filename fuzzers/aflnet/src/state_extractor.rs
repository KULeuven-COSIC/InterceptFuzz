use serde::{Deserialize, Serialize};
use std::fmt;

pub const STATE_INITIAL: u32 = 0x10000000;
pub const STATE_ERROR: u32 = 0xFFFFFFFF;

// 1. The Wrapper
#[derive(Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct MleState(pub u32);

// 2. Implement a custom Debug trait that outputs the clean string!
impl fmt::Debug for MleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_name = match self.0 {
            0 => "Link Request",
            1 => "Link Accept",
            2 => "Link Accept/Request",
            3 => "Link Reject",
            4 => "Advertisement",
            5 => "Update",
            6 => "Update Request",
            7 => "Data Request",
            8 => "Data Response",
            9 => "Parent Request",
            10 => "Parent Response",
            11 => "Child ID Request",
            12 => "Child ID Response",
            13 => "Child Update Request",
            14 => "Child Update Response",
            15 => "Announce",
            16 => "Discovery Request",
            17 => "Discovery Response",
            _ => return write!(f, "Unknown_Command_{}", self.0),
        };
        // Write the string cleanly without quotes or struct names
        write!(f, "{}", state_name)
    }
}

/// Your custom OpenThread MLE Dissector
pub fn dissect_mle_type(packet: &[u8]) -> u32 {
    let mut mle_start = None;
    
    // Hunt for the magic MLE header
    for i in 0..packet.len().saturating_sub(4) {
        if packet[i] == 0xF0 && packet[i+1] == 0x4D && 
           packet[i+2] == 0x4C && packet[i+3] == 0x4D && packet[i+4] == 0x4C {
            mle_start = Some(i + 7); 
            break;
        }
    }

    if let Some(start) = mle_start {
        if start + 11 < packet.len() {
            return packet[start + 11] as u32;
        }
    }

    // // Log malformed/unknown packets to disk for manual review
    // if let Ok(mut file) = OpenOptions::new()
    //     .create(true)
    //     .append(true)
    //     .open("unknown_packets.log") 
    // {
    //     let hex_dump: String = packet.iter().map(|b| format!("{:02X} ", b)).collect();
    //     let _ = writeln!(file, "[!] Unknown Packet (Len: {}): {}", packet.len(), hex_dump);
    // }
    
    STATE_ERROR
}

/// Reads the outbox shared memory, extracts target responses, and returns the sequence of protocol states.
pub fn extract_states_from_outbox(outbox_ptr: *mut u8) -> Vec<MleState> {
    let mut states = Vec::new();

    unsafe {
        // Read the 4-byte Total Size header at the start of the outbox
        const MAX_CAPACITY: usize = 1024 * 1024 - 4;
        let raw_total = *(outbox_ptr as *const u32) as usize;
        let total_bytes = std::cmp::min(raw_total, MAX_CAPACITY);
        let mut cursor = 4;

        while cursor < 4 + total_bytes {
            let direction = *outbox_ptr.add(cursor);
            let len_low = *outbox_ptr.add(cursor + 1);
            let len_high = *outbox_ptr.add(cursor + 2);
            let packet_len = (len_low as usize) | ((len_high as usize) << 8);
            
            if cursor + 3 + packet_len > 4 + total_bytes {
                break;
            }

            cursor += 3;

            // We only care about how the TARGET responded (Direction 0x01)
            if direction == 0x01 { 
                let slice = std::slice::from_raw_parts(outbox_ptr.add(cursor), packet_len);
                let state = dissect_mle_type(slice);
                states.push(MleState(state));
            }

            cursor += packet_len;
        }
    }

    states
}