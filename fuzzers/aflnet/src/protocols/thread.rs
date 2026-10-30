use serde::{Deserialize, Serialize};
use std::fmt;

use crate::protocols::protocol::{Protocol, STATE_ERROR};

#[derive(Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct MleState(pub u32);

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
        write!(f, "{}", state_name)
    }
}

pub struct MleProtocol;

impl Protocol for MleProtocol {
    type State = MleState;

    fn type_to_state(packet_type: u8) -> Self::State {
        MleState(packet_type.into())
    }

    fn should_keep(state: &Self::State) -> bool {
        // Only ignore STATE_ERROR for MLE
        state.0 != STATE_ERROR
    }

    fn get_max_packet_size() -> u32 {
        return 127; // OpenThread OT_RADIO_FRAME_MAX_SIZE.
    }
}
