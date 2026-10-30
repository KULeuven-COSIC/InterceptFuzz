use libafl::observers::Observer;
use libafl_bolts::Named;
use std::borrow::Cow;

/// An observer that tracks how many packets from the input sequence
/// were actually consumed/processed by the OpenThread target.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConsumedObserver {
    name: Cow<'static, str>,
    pub consumed_count: usize,
}

impl ConsumedObserver {
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            consumed_count: 0,
        }
    }
}

// Implement the core LibAFL Observer trait (marker trait for this use case)
impl<I, S> Observer<I, S> for ConsumedObserver {}

// Implement the Named trait so we can find it in the observer tuple
impl Named for ConsumedObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}