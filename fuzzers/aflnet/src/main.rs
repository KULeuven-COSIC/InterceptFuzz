pub mod cap_len;
pub mod consumed_observer;
pub mod protocols;
pub mod replay_export;

use std::collections::HashSet;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use libafl::corpus::OnDiskCorpus;
use libafl::feedback_and_fast;
use libafl::{
    Error,
    corpus::{CachedOnDiskCorpus, Corpus},
    events::{ProgressReporter, SimpleEventManager},
    executors::{Executor, ExitKind, HasObservers, forkserver::ForkserverExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::StdScheduledMutator,
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::powersched::{BaseSchedule, PowerSchedule},
    schedulers::{IndexesLenTimeMinimizerScheduler, StdWeightedScheduler},
    stages::StdPowerMutationalStage,
    state::{HasCorpus, HasExecutions, HasMaxSize, HasSolutions, StdState},
};

use libafl_bolts::{
    HasLen, current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{MatchName, tuple_list},
};

use butterfly_fuzz::{
    GraphvizMonitor, PacketCrossoverInsertMutator, PacketCrossoverReplaceMutator,
    PacketDeleteMutator, PacketDuplicateMutator, PacketHavocMutator, PacketReorderMutator,
    PacketSpliceMutator, StateFeedback, StateMonitor, StateObserver, supported_havoc_mutations,
};
use netfuzzbench_common::{Delimited, OpaquePacket, Packet, Packets};

use crate::cap_len::CapLenMutator;
use crate::consumed_observer::ConsumedObserver;
use crate::replay_export::ReplayExportFeedback;

// Import the unified Protocol trait and implementations
use crate::protocols::lte::{LteProtocol, LteState};
use crate::protocols::protocol::{Protocol, extract_states_from_outbox};
use crate::protocols::thread::{MleProtocol, MleState};
use crate::protocols::wifi::{WifiProtocol, WifiState};

// =========================================================================
// 1. THE PROTOCOL BRIDGE (Dummy Delimiter)
// =========================================================================
#[derive(Clone, Debug, Default, Hash, serde::Serialize, serde::Deserialize)]
pub struct OtDelim;

impl Delimited for OtDelim {
    fn to_bytes_extend(buf: &[u8], vec: &mut Vec<u8>) {
        vec.extend_from_slice(buf);
    }

    fn delimit(buf: &[u8]) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        Some(buf.len())
    }
}
type OtPacket = OpaquePacket<OtDelim>;

// =========================================================================
// 2. THE EXECUTION WRAPPER (Flatten & Spy)
// =========================================================================
// Made OtExecutor generic over P (the Protocol)
pub struct OtExecutor<E, P> {
    pub inner: E,
    pub outbox_ptr: *mut u8,
    pub is_bootstrapping: bool,
    pub ignore_direction: bool, // Added field to store the flag in the executor
    pub phantom: PhantomData<P>, // Required to hold the generic type P
}

impl<EM, E, OT, S, Z, P> Executor<EM, Packets<OtPacket>, S, Z> for OtExecutor<E, P>
where
    E: Executor<EM, BytesInput, S, Z> + HasObservers<Observers = OT>,
    OT: MatchName,
    P: Protocol, // Ensure P is a valid protocol (MLE or WiFi)
    P::State: serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + Clone
        + std::cmp::Eq
        + std::hash::Hash
        + 'static,
{
    #[allow(deprecated)]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &Packets<OtPacket>,
    ) -> Result<ExitKind, Error> {
        if input.len() > 16 {
            return Ok(ExitKind::Ok);
        }

        let mut inner_stream = Vec::new();
        for packet in input.iter() {
            let payload = packet.to_bytes();

            // CRITICAL FIX: Truncate packet payload to the protocol's max packet size
            let max_packet_size = P::get_max_packet_size();
            let safe_len = std::cmp::min(payload.len(), max_packet_size as usize) as u32;

            inner_stream.extend_from_slice(&safe_len.to_be_bytes());
            inner_stream.extend_from_slice(&payload[..safe_len as usize]);
        }

        let mut flat_buffer = Vec::with_capacity(4 + inner_stream.len());
        let total_len = inner_stream.len() as u32;
        flat_buffer.extend_from_slice(&total_len.to_be_bytes());
        flat_buffer.extend_from_slice(&inner_stream);

        if flat_buffer.is_empty() {
            flat_buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }

        let bytes_input = BytesInput::new(flat_buffer);
        let exit_kind = self.inner.run_target(fuzzer, state, mgr, &bytes_input)?;

        // Dynamically extract states based on the generic Protocol (P)
        let target_states = extract_states_from_outbox::<P>(self.outbox_ptr, self.ignore_direction);

        let mut consumed_packets = 0;
        unsafe {
            const MAX_CAPACITY: usize = (1024 * 1024) - 4;
            let raw_total = *(self.outbox_ptr as *const u32) as usize;
            let total_bytes = std::cmp::min(raw_total, MAX_CAPACITY);
            let mut cursor = 4;

            while cursor < 4 + total_bytes {
                // BUGFIX: Updated to parse the new 6-byte header: [1b Dir] [1b Type] [4b Len BE]
                let direction = *self.outbox_ptr.add(cursor);

                let len_b0 = *self.outbox_ptr.add(cursor + 2) as usize;
                let len_b1 = *self.outbox_ptr.add(cursor + 3) as usize;
                let len_b2 = *self.outbox_ptr.add(cursor + 4) as usize;
                let len_b3 = *self.outbox_ptr.add(cursor + 5) as usize;
                let packet_len = (len_b0 << 24) | (len_b1 << 16) | (len_b2 << 8) | len_b3;

                // Ensure we don't go out of bounds (cursor + 6 header bytes + payload)
                if cursor + 6 + packet_len > 4 + total_bytes {
                    break;
                }

                // Check condition with the new ignore_direction flag
                if direction == 0x00 || self.ignore_direction {
                    consumed_packets += 1;
                }

                // Advance the cursor past the 6-byte header and the payload
                cursor += 6 + packet_len;
            }
        }

        if let Some(obs) = self
            .inner
            .observers_mut()
            .match_name_mut::<ConsumedObserver>("consumed_obs")
        {
            obs.consumed_count = consumed_packets;
        }

        // Generic state observer lookup
        if let Some(state_obs) = self
            .inner
            .observers_mut()
            .match_name_mut::<StateObserver<P::State>>("state_observer")
        {
            for s in target_states {
                state_obs.record(&s);
            }
        }

        if !self.is_bootstrapping {
            unsafe {
                std::ptr::write_bytes(self.outbox_ptr, 0, 4);
            }
        }

        Ok(exit_kind)
    }
}

impl<E, OT, P> HasObservers for OtExecutor<E, P>
where
    E: HasObservers<Observers = OT>,
{
    type Observers = OT;
    fn observers(&self) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
        self.inner.observers()
    }
    fn observers_mut(
        &mut self,
    ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
        self.inner.observers_mut()
    }
}

fn parse_log_filters() -> (HashSet<String>, Option<HashSet<String>>) {
    // ... [Matches your existing code] ...
    let mut blacklist = HashSet::new();
    if let Ok(env_val) = std::env::var("FUZZ_BLACKLIST") {
        for item in env_val.split(',') {
            let trimmed = item.trim().to_lowercase();
            if !trimmed.is_empty() {
                blacklist.insert(trimmed);
            }
        }
    }
    let mut whitelist = None;
    if let Ok(env_val) = std::env::var("FUZZ_WHITELIST") {
        let trimmed_val = env_val.trim().to_lowercase();
        if !trimmed_val.is_empty() && trimmed_val != "*" {
            let mut set = HashSet::new();
            for item in trimmed_val.split(',') {
                let trimmed_item = item.trim().to_string();
                if !trimmed_item.is_empty() {
                    set.insert(trimmed_item);
                }
            }
            whitelist = Some(set);
        }
    }
    (blacklist, whitelist)
}

pub fn generate_fuzzer_stats<S, I>(state: &S, out_dir: &str, start_time_secs: u64)
where
    S: HasCorpus<I> + HasSolutions<I> + HasExecutions,
{
    // ... [Matches your existing code] ...
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let run_time = current_time.saturating_sub(start_time_secs);
    let execs_done = *state.executions();
    let execs_per_sec = if run_time > 0 {
        execs_done as f64 / run_time as f64
    } else {
        0.0
    };

    let corpus_count = state.corpus().count();
    let saved_crashes = state.solutions().count();

    let stats = format!(
        "start_time        : {start_time_secs}\n\
         last_update       : {current_time}\n\
         run_time          : {run_time}\n\
         fuzzer_pid        : {pid}\n\
         execs_done        : {execs_done}\n\
         execs_per_sec     : {execs_per_sec:.2}\n\
         corpus_count      : {corpus_count}\n\
         saved_crashes     : {saved_crashes}\n\
         ",
        start_time_secs = start_time_secs,
        current_time = current_time,
        run_time = run_time,
        pid = std::process::id(),
        execs_done = execs_done,
        execs_per_sec = execs_per_sec,
        corpus_count = corpus_count,
        saved_crashes = saved_crashes,
    );

    let stats_path = format!("{}/fuzzer_stats", out_dir);
    if let Err(e) = fs::write(&stats_path, stats) {
        eprintln!("[!] Failed to write fuzzer_stats: {}", e);
    } else {
        println!("[+] Generated AFL-compatible stats file at {}", stats_path);
    }
}

// =========================================================================
// 3. THE MAIN FUZZER MACRO
// =========================================================================
// This macro prevents duplicating 300 lines of boilerplate for each protocol type.
macro_rules! run_fuzz_campaign {
    ($ProtocolType:ty, $StateType:ty) => {
        let start_time_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let out_dir_str =
            std::env::var("OUT_DIR").unwrap_or_else(|_| "./fuzzer_output".to_string());
        let harness_path = std::env::var("FUZZ_TARGET").expect("FUZZ_TARGET env var must be set");
        let overwrite = std::env::var("OVERWRITE")
            .map(|v| v == "1")
            .unwrap_or(false);
        let timeout_secs: Option<u64> = std::env::var("TIMEOUT").ok().and_then(|v| v.parse().ok());

        // Read IGNORE_DIRECTION env var
        let ignore_direction = std::env::var("IGNORE_DIRECTION")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let out_dir = PathBuf::from(&out_dir_str);
        if out_dir.exists() && !overwrite {
            eprintln!(
                "\n[!] ERROR: Output directory '{}' already exists!",
                out_dir_str
            );
            eprintln!(
                "[!] To overwrite this campaign, run with: OVERWRITE=1 OUT_DIR={}",
                out_dir_str
            );
            std::process::exit(1);
        }

        println!("Initializing AFLNet/Fizzle Baseline Comparison Fuzzer...");
        println!(" -> Target: {}", harness_path);
        println!(" -> Output Directory: {}", out_dir_str);
        if ignore_direction {
            println!(
                " -> Mode: Ignoring packet direction block checking (Executing for all packets)."
            );
        }

        if overwrite && out_dir.exists() {
            std::fs::remove_dir_all(&out_dir).expect("Failed to delete old output directory");
        }

        std::fs::create_dir_all(&out_dir).unwrap();
        std::env::set_current_dir(&out_dir).unwrap();

        let crashes_dir = PathBuf::from("crashes");
        let queue_dir = PathBuf::from("queue");
        let replay_queue_dir = PathBuf::from("replayable_queue");
        let replay_crashes_dir = PathBuf::from("replayable_crashes");

        std::fs::create_dir_all(&crashes_dir).unwrap();
        std::fs::create_dir_all(&queue_dir).unwrap();
        std::fs::create_dir_all(&replay_queue_dir).unwrap();
        std::fs::create_dir_all(&replay_crashes_dir).unwrap();

        let mut shmem_provider = StdShMemProvider::new().expect("Failed to init ShMem");

        const MAP_SIZE: usize = 2621440;
        let mut coverage_shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
        unsafe {
            std::env::set_var("__AFL_SHM_ID", coverage_shmem.id().to_string());
        }

        let mut outbox_shmem = shmem_provider.new_shmem(1024 * 1024).unwrap();
        let outbox_ptr = outbox_shmem.as_mut_ptr();
        unsafe {
            std::env::set_var("OUTBOX_SHMEM_ID", outbox_shmem.id().to_string());
        }

        let observer =
            unsafe { StdMapObserver::from_mut_ptr("edges", coverage_shmem.as_mut_ptr(), MAP_SIZE) };

        let edges_observer = HitcountsMapObserver::new(observer).track_indices();
        let time_observer = TimeObserver::new("time");
        let consumed_obs = ConsumedObserver::new("consumed_obs");

        // Use the macro's state type here
        let state_observer = StateObserver::<$StateType>::new("state_observer");

        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let state_feedback = StateFeedback::new(&state_observer);
        let time_feedback = TimeFeedback::new(&time_observer);

        let combined_feedback = feedback_or!(map_feedback, state_feedback, time_feedback);
        let mut feedback = ReplayExportFeedback::new(combined_feedback, replay_queue_dir);

        let crash_corpus = OnDiskCorpus::new(crashes_dir.clone()).unwrap();
        let queue_corpus = CachedOnDiskCorpus::new(queue_dir.clone(), 4096).unwrap();

        let crash_map_feedback = MaxMapFeedback::with_name("crash_edges", &edges_observer);
        let crash_feedback = ReplayExportFeedback::new(CrashFeedback::new(), replay_crashes_dir);
        let mut objective = feedback_and_fast!(crash_map_feedback, crash_feedback);

        let mut state = StdState::new(
            StdRand::with_seed(current_nanos()),
            queue_corpus,
            crash_corpus,
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_max_size(<$ProtocolType>::get_max_packet_size() as usize);

        let ps = PowerSchedule::new(BaseSchedule::EXPLORE);
        let weighted_scheduler =
            StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(ps));
        let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, weighted_scheduler);

        let (blacklist, whitelist) = parse_log_filters();
        let state_monitor = StateMonitor::new()
            .with_blacklist(blacklist)
            .with_whitelist(whitelist);

        let dot_file_path = out_dir.join("stategraph.dot");
        let monitor = GraphvizMonitor::new(
            state_monitor,
            dot_file_path.to_string_lossy().to_string(),
            60,
        );

        let mut mgr = SimpleEventManager::new(monitor);
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let forkserver = ForkserverExecutor::builder()
            .program(harness_path)
            .shmem_provider(&mut shmem_provider)
            .is_persistent(true)
            .coverage_map_size(MAP_SIZE)
            .timeout(Duration::from_millis(3000))
            //.debug_child(true)
            .build(tuple_list!(
                edges_observer,
                state_observer,
                consumed_obs,
                time_observer
            ))
            .expect("Failed to create the Forkserver Executor");

        let mut executor = OtExecutor {
            inner: forkserver,
            outbox_ptr,
            is_bootstrapping: true,
            ignore_direction, // Pass the environment flag down to the executor
            phantom: PhantomData::<$ProtocolType>, // Assign the generic protocol here
        };

        if state.corpus().count() == 0 {
            println!("[*] Bootstrapping initial sequence (empty trigger)...");

            let empty_trigger = Packets::new(vec![]);
            executor
                .run_target(&mut fuzzer, &mut state, &mut mgr, &empty_trigger)
                .expect("Failed to execute harvest run");

            let mut seed_packets: Vec<OtPacket> = Vec::new();
            let mut req_count = 0;

            unsafe {
                const MAX_CAPACITY: usize = (1024 * 1024) - 4;
                let raw_total = *(outbox_ptr as *const u32) as usize;
                let total_bytes = std::cmp::min(raw_total, MAX_CAPACITY);
                let mut cursor = 4;

                while cursor < 4 + total_bytes {
                    // Read the new 6-byte header: [1b Dir] [1b Type] [4b Len BE]
                    let direction = *outbox_ptr.add(cursor);
                    // We can ignore the packet_type (*outbox_ptr.add(cursor + 1))
                    // because we only care about extracting the raw payload for the seeds

                    let len_b0 = *outbox_ptr.add(cursor + 2) as usize;
                    let len_b1 = *outbox_ptr.add(cursor + 3) as usize;
                    let len_b2 = *outbox_ptr.add(cursor + 4) as usize;
                    let len_b3 = *outbox_ptr.add(cursor + 5) as usize;
                    let packet_len = (len_b0 << 24) | (len_b1 << 16) | (len_b2 << 8) | len_b3;

                    // Ensure we don't go out of bounds
                    if packet_len == 0 || cursor + 6 + packet_len > 4 + total_bytes {
                        break;
                    }

                    // Move the cursor past the 6-byte header
                    cursor += 6;

                    // Check condition with the new ignore_direction flag
                    if direction == 0x00 || ignore_direction {
                        // Extract just the payload bytes to use as a seed
                        let packet_slice =
                            std::slice::from_raw_parts(outbox_ptr.add(cursor), packet_len);
                        seed_packets.push(OtPacket::new(packet_slice));
                        req_count += 1;
                    }

                    // Move the cursor past the payload to the next packet
                    cursor += packet_len;
                }
                println!(
                    "[+] Harvested {} genuine Request packets into the initial seed.",
                    req_count
                );
            }

            let initial_seeds = Packets::new(seed_packets);
            println!("Evaluating the harvested seeds");
            fuzzer
                .evaluate_input(&mut state, &mut executor, &mut mgr, &initial_seeds)
                .expect("Failed to evaluate initial dynamically harvested sequence");
        }

        executor.is_bootstrapping = false;

        // let mutation = StdScheduledMutator::new(tuple_list!(
        //     PacketReorderMutator::new(),
        //     PacketDeleteMutator::new(2),
        //     PacketDuplicateMutator::new(16),
        //     PacketCrossoverInsertMutator::new(),
        //     PacketCrossoverReplaceMutator::new(),
        //     PacketSpliceMutator::new(2),
        //     PacketHavocMutator::new(supported_havoc_mutations()),
        // ));

        let mutation = CapLenMutator::new(
            StdScheduledMutator::new(tuple_list!(
                PacketReorderMutator::new(),
                PacketDeleteMutator::new(2),
                PacketDuplicateMutator::new(16),
                PacketCrossoverInsertMutator::new(),
                PacketCrossoverReplaceMutator::new(),
                PacketSpliceMutator::new(2),
                PacketHavocMutator::new(supported_havoc_mutations()),
            )),
            <$ProtocolType>::get_max_packet_size() as usize,
            |b: &[u8]| OtPacket::new(b),
        );

        let mutational_stage =
            StdPowerMutationalStage::<_, _, Packets<OtPacket>, _, _, _>::new(mutation);
        let mut stages = tuple_list!(mutational_stage);

        println!("Starting Stateful Fuzzing Loop...");

        if let Some(secs) = timeout_secs {
            println!(
                " -> Timeout Set: Fuzzer will stop automatically after {} seconds.",
                secs
            );
            let timeout = std::time::Duration::from_secs(secs);
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout {
                fuzzer
                    .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
                    .expect("Error in fuzzing loop");
                mgr.maybe_report_progress(&mut state, libafl_bolts::current_time())
                    .unwrap();
            }
            println!(
                "==> Maximum fuzzing time ({}s) reached. Shutting down gracefully.",
                secs
            );
            generate_fuzzer_stats(&state, &out_dir_str, start_time_secs);
        } else {
            println!(" -> Mode: Continuous Fuzzing (Press Ctrl+C to stop).");
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Error in fuzzing loop");
        }
        println!("Fuzzing campaign stopped gracefully.");
    };
}

fn main() {
    // Determine which protocol to fuzz from the PROTOCOL environment variable
    let protocol_env = std::env::var("PROTOCOL")
        .unwrap_or_else(|_| "MLE".to_string())
        .to_uppercase();

    match protocol_env.as_str() {
        "WIFI" => {
            println!("[*] Protocol selected: WiFi");
            run_fuzz_campaign!(WifiProtocol, WifiState);
        }
        "MLE" | "THREAD" => {
            println!("[*] Protocol selected: OpenThread/MLE");
            run_fuzz_campaign!(MleProtocol, MleState);
        }
        "LTE" | "4G" => {
            println!("[*] Protocol selected: LTE/4G");
            run_fuzz_campaign!(LteProtocol, LteState);
        }
        _ => {
            eprintln!(
                "[!] Unknown PROTOCOL '{}'. Please use 'MLE' or 'WIFI'.",
                protocol_env
            );
            std::process::exit(1);
        }
    }
}
