use serde::{Deserialize, Serialize};
use std::fmt;

use crate::protocols::protocol::{Protocol, STATE_ERROR};

#[derive(Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct LteState(pub u32);

impl fmt::Debug for LteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_name = match self.0 {
            0x01 => "RRC Connection Request",
            0x02 => "RRC Connection Setup",
            0x03 => "RRC Connection Setup Complete",
            0x04 => "RRC Connection Reject",
            0x05 => "RRC Connection Reconfiguration",
            0x06 => "RRC Connection Reconfiguration Complete",
            0x07 => "RRC Connection Reestablishment Request",
            0x08 => "RRC Connection Reestablishment",
            0x09 => "RRC Connection Reestablishment Complete",
            0x0A => "RRC Connection Reestablishment Reject",
            0x0B => "Measurement Report",
            0xFF => "Unknown/Error",
            _ => return write!(f, "Unknown_State_ID_{}", self.0),
        };
        write!(f, "{}", state_name)
    }
}

pub struct LteProtocol;

impl Protocol for LteProtocol {
    type State = LteState;

    fn type_to_state(packet_type: u8) -> Self::State {
        LteState(packet_type.into())
    }

    fn should_keep(state: &Self::State) -> bool {
        state.0 != STATE_ERROR
    }

    fn get_max_packet_size() -> u32 {
        // SRB0 messages are small (e.g., 2048), but SRB1 messages like
        // RRC Connection Reconfiguration can be quite large.
        return 8192;
    }
}
