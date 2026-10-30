// cap_len.rs
//
// Wraps any mutator over Packets<P> and truncates every packet to `max_len`
// bytes after each mutation. The executor already truncates packets before
// they reach the harness, so the target sees the same bytes as before. The
// difference is on the fuzzer side: packets no longer grow beyond the frame
// size, havoc no longer spends mutations on bytes that are cut off anyway, and
// the queue and replayable_queue store exactly what was executed.

use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::Named;
use netfuzzbench_common::{Packet, Packets};

pub struct CapLenMutator<M, P> {
    inner: M,
    max_len: usize,
    make_packet: fn(&[u8]) -> P, // e.g. OtPacket::new
    name: Cow<'static, str>,
}

impl<M: Named, P> CapLenMutator<M, P> {
    pub fn new(inner: M, max_len: usize, make_packet: fn(&[u8]) -> P) -> Self {
        let name = Cow::Owned(format!("CapLen<{}>", inner.name()));
        Self {
            inner,
            max_len,
            make_packet,
            name,
        }
    }
}

impl<M, P> Named for CapLenMutator<M, P> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<M, P, S> Mutator<Packets<P>, S> for CapLenMutator<M, P>
where
    M: Mutator<Packets<P>, S>,
    P: Packet + Clone,
{
    fn mutate(&mut self, state: &mut S, input: &mut Packets<P>) -> Result<MutationResult, Error> {
        let result = self.inner.mutate(state, input)?;

        if input.iter().any(|p| p.to_bytes().len() > self.max_len) {
            let capped: Vec<P> = input
                .iter()
                .map(|p| {
                    let bytes = p.to_bytes();
                    if bytes.len() > self.max_len {
                        (self.make_packet)(&bytes[..self.max_len])
                    } else {
                        p.clone()
                    }
                })
                .collect();
            *input = Packets::new(capped);
        }
        Ok(result)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}
