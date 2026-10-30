use libafl::{
    Error,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
};
use libafl_bolts::{HasLen, Named, tuples::MatchName};
use netfuzzbench_common::{Packet, Packets};
use std::borrow::Cow;
use std::path::PathBuf;

use crate::consumed_observer::ConsumedObserver;

/// A custom feedback wrapper that saves every interesting seed with a UNIX timestamp.
/// It flattens the `Packets` sequence into OpenThread LV-framed bytes before saving.
pub struct ReplayExportFeedback<F> {
    pub inner: F,
    replay_dir: PathBuf,
}

impl<F> ReplayExportFeedback<F> {
    pub fn new(inner: F, replay_dir: PathBuf) -> Self {
        Self { inner, replay_dir }
    }
}

impl<F> Named for ReplayExportFeedback<F>
where
    F: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

// Ensure it can initialize the state of the inner feedbacks (like MaxMapFeedback or StateFeedback)
impl<F, S> StateInitializer<S> for ReplayExportFeedback<F>
where
    F: StateInitializer<S>,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.init_state(state)
    }
}

// The core logic: intercept 'is_interesting' and save the file
impl<EM, F, OT, S, P> Feedback<EM, Packets<P>, OT, S> for ReplayExportFeedback<F>
where
    F: Feedback<EM, Packets<P>, OT, S>,
    P: Packet + Clone, // Added Clone bound so we can trim and reconstruct the Vec
    OT: MatchName,     // Added MatchName bound to find the ConsumedObserver
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &Packets<P>,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        // 1. Evaluate the inner combined feedback (Map OR State)
        let is_interesting = self
            .inner
            .is_interesting(state, manager, input, observers, exit_kind)?;

        // 2. If EITHER feedback found it interesting, export it!
        if is_interesting {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis();

            let filename = format!("standalone_state_{}.bin", timestamp);
            let filepath = self.replay_dir.join(filename);

            // --- TRIMMING LOGIC FOR BINARY EXPORT ---
            // Find out how many packets the target actually consumed
            #[allow(deprecated)]
            let consumed = observers
                .match_name::<ConsumedObserver>("consumed_obs")
                .map(|obs| obs.consumed_count)
                .unwrap_or(input.len());

            // Fallback to full input if consumed is 0 (e.g. during bootstrap edge cases)
            let write_len = if consumed > 0 {
                std::cmp::min(consumed, input.len())
            } else {
                input.len()
            };

            let mut inner_stream = Vec::new();
            for packet in input.iter().take(write_len) {
                let payload = packet.to_bytes();
                let safe_len = std::cmp::min(payload.len(), u32::MAX as usize) as u32;
                inner_stream.extend_from_slice(&safe_len.to_be_bytes());
                inner_stream.extend_from_slice(&payload[..safe_len as usize]);
            }

            let mut tlv_buffer = Vec::with_capacity(4 + inner_stream.len());
            let total_len = inner_stream.len() as u32;
            tlv_buffer.extend_from_slice(&total_len.to_be_bytes());
            tlv_buffer.extend_from_slice(&inner_stream);

            if !tlv_buffer.is_empty() {
                if let Ok(mut file) = std::fs::File::create(&filepath) {
                    use std::io::Write;
                    let _ = file.write_all(&tlv_buffer);
                    // println!("==> [Replay Export] Saved trimmed LV sequence ({} pkts) to {:?}", write_len, filepath);
                }
            }
        }

        Ok(is_interesting)
    }

    #[inline]
    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<Packets<P>>,
    ) -> Result<(), Error> {
        // // The AFL++ Power Schedulers mathematically require an execution time.
        // // Since we bypassed the CalibrationStage, we inject a dummy time here to satisfy it.
        // testcase.set_exec_time(std::time::Duration::from_millis(1));
        // --- TRIMMING LOGIC FOR CORPUS DISK CACHE ---
        // 1. Read how many packets the target actually consumed
        #[allow(deprecated)]
        if let Some(obs) = observers.match_name::<ConsumedObserver>("consumed_obs") {
            let consumed = obs.consumed_count;

            // 2. If the fuzzer sent more packets than the target processed, trim it!
            if let Some(current_input) = testcase.input() {
                if consumed > 0 && consumed < current_input.len() {
                    // Create a new sequence with only the consumed packets
                    let trimmed_vec: Vec<P> =
                        current_input.iter().take(consumed).cloned().collect();

                    // Replace the bloated input with the trimmed input in the testcase
                    *testcase.input_mut() = Some(Packets::new(trimmed_vec));
                }
            }
        }

        self.inner
            .append_metadata(state, manager, observers, testcase)
    }

    #[inline]
    fn last_result(&self) -> Result<bool, Error> {
        self.inner.last_result()
    }
}
