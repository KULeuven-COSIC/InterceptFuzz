use serde::{Deserialize, Serialize};
use std::fmt;

use crate::protocols::protocol::{Protocol, STATE_ERROR};

#[derive(Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiState(pub u32);

impl fmt::Debug for WifiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_name = match self.0 {
            0 => "Association Request",
            1 => "Association Response",
            2 => "Reassociation Request",
            3 => "Reassociation Response",
            4 => "Probe Request",
            5 => "Probe Response",
            8 => "Beacon",
            10 => "Disassociation",
            11 => "Authentication",
            12 => "Deauthentication",
            13 => "Action",
            100 => "Data Frame",
            101 => "Control Frame",
            0xFF => "Unknown/Error",
            _ => return write!(f, "Unknown_State_ID_{}", self.0),
        };
        write!(f, "{}", state_name)
    }
}

pub struct WifiProtocol;

impl Protocol for WifiProtocol {
    type State = WifiState;

    fn type_to_state(packet_type: u8) -> Self::State {
        WifiState(packet_type.into())
    }

    fn should_keep(state: &Self::State) -> bool {
        state.0 != STATE_ERROR
    }

    fn get_max_packet_size() -> u32 {
        return 1500; // Standard MTU
    }
}
