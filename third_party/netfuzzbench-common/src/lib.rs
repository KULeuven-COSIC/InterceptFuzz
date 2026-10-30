use std::{cmp, fs::File};
use std::io::Read;
use std::path::Path;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use butterfly_fuzz::{HasCrossoverInsertMutation, HasCrossoverReplaceMutation, HasHavocMutation, HasPackets, HasSpliceMutation};
use libafl::{
    inputs::{BytesInput, Input, TargetBytesConverter},
    mutators::{MutationId, MutationResult, MutatorsTuple},
    state::{HasMaxSize, HasRand},
    Error,
};
use libafl_bolts::fs::write_file_atomic;
use libafl_bolts::{ownedref::OwnedSlice, HasLen};
use serde::de::DeserializeOwned;

pub trait Packet: Clone + Debug + Default + Hash + serde::Serialize {
    fn from_stream(stream: &[u8]) -> Option<Vec<Self>>;

    fn from_bytes(data: &[u8]) -> Option<Self>;

    fn to_bytes_extend(&self, v: &mut Vec<u8>);

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.to_bytes_extend(&mut v);
        v
    }
}

pub trait Delimited: Clone + Debug + Default + Hash + Sized + 'static {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>);

    fn to_bytes(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        Self::to_bytes_extend(data, &mut v);
        v
    }

    fn delimit(data: &[u8]) -> Option<usize>;
}

#[derive(Clone, Debug, Default, Hash, serde::Serialize, serde::Deserialize)]
pub struct Packets<P>
where
    P: Packet,
{
    pkts: Vec<P>,
}

impl<P> Packets<P>
where
    P: Packet,
{
    pub fn new(pkts: Vec<P>) -> Self {
        Self {
            pkts,
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, P> {
        self.pkts.iter()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0u8; 4]);
        for pkt in &self.pkts {
            let start_idx = v.len();
            v.extend_from_slice(&[0u8; 4]);
            pkt.to_bytes_extend(&mut v);
            let pkt_len = (v.len() - 4) - start_idx;
            v[start_idx..start_idx + 4].copy_from_slice(&u32::to_be_bytes(pkt_len as u32));
        }

        let data_len = v.len() - 4;
        v[0..4].copy_from_slice(&u32::to_be_bytes(data_len as u32));

        v
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        Some(Self::new(P::from_stream(data).filter(|p| !p.is_empty())?))
    }
}

impl<P> Input for Packets<P>
where 
    P: Packet + DeserializeOwned
{
     /// Write this input to the file
    fn to_file<T>(&self, path: T) -> Result<(), Error>
    where
        T: AsRef<Path>,
    {
        let mut bytes = Vec::new();
        for p in self.iter() {
            p.to_bytes_extend(&mut bytes);
        }

        write_file_atomic(path, &bytes)
    }

    /// Load the content of this input from a file
    fn from_file<T>(path: T) -> Result<Self, Error>
    where
        T: AsRef<Path>,
    {
        let mut file = File::open(&path)?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        let pkt_vec_res = P::from_stream(&bytes).filter(|p| !p.is_empty()).ok_or(Error::serialize("failed to serialize corpus input"));
        if pkt_vec_res.is_err() {
            log::error!("failed to deserialize any packets from file {:?}", path.as_ref());
        }

        Ok(Packets::new(pkt_vec_res?))
    }   
}

impl<P> HasPackets<P> for Packets<P>
where 
    P: Packet,
{
    fn packets(&self) -> &[P] {
        self.pkts.as_slice()
    }

    fn packets_mut(&mut self) -> &mut Vec<P> {
        &mut self.pkts
    }
}

impl<P> HasLen for Packets<P>
where 
    P: Packet,
{
    fn len(&self) -> usize {
        self.pkts.len()
    }
}

/*
impl<MT, P, S> HasPcapRepresentation<Packets<MT, P, S>> for Packets<MT, P, S>
where 
    MT: MutatorsTuple<BytesInput, S>,
    P: Packet<MT, S>,
    S: HasMaxSize + HasRand,
{
    fn from_pcap(capture: pcap::Capture<pcap::Offline>) -> Result<Self, libafl::Error> {
        let pkts = P::from_pcap(capture).unwrap();
        
        Ok(Packets {
            pkts
        })
    }
}
*/

pub struct PacketsTargetBytesConverter;

impl<PKT> TargetBytesConverter<Packets<PKT>> for PacketsTargetBytesConverter
where
    PKT: Packet,
{
    fn to_target_bytes<'a>(&mut self, input: &'a Packets<PKT>) -> OwnedSlice<'a, u8> {
        /*
        let mut v = Vec::new();
        v.extend_from_slice(&u32::to_be_bytes(input.pkts.len() as u32));
        for pkt in input.iter() {
            let len_idx = v.len();
            v.extend_from_slice(&[0u8; 4]);
            pkt.to_bytes_extend(&mut v);
            let pkt_len = v.len() - (len_idx + 4);
            v[len_idx..len_idx + 4].copy_from_slice(&u32::to_be_bytes(pkt_len as u32));
        }

        v.into()
        */

        input.to_bytes().into()
    }
}

#[derive(Clone, Debug, Default, Hash, serde::Serialize, serde::Deserialize)]
pub struct OpaquePacket<D: Delimited> {
    data: BytesInput,
    #[serde(skip)]
    _phantom: PhantomData<D>,
}

impl<D: Delimited> OpaquePacket<D> {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: BytesInput::from(data),
            _phantom: Default::default(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        D::to_bytes(self.data.as_ref())
    }
}

impl<D> Packet for OpaquePacket<D>
where 
    D: Delimited,
{
    fn from_stream(mut stream: &[u8]) -> Option<Vec<Self>> {
        let mut pkts = Vec::new();

        while let Some(end_idx) = D::delimit(stream) {
            pkts.push(OpaquePacket::new(&stream[..end_idx]));
            stream = &stream[end_idx..];
        }

        Some(pkts)
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        let end_idx = D::delimit(data)?;

        Some(OpaquePacket::new(&data[..end_idx]))
    }

    fn to_bytes_extend(&self, v: &mut Vec<u8>) {
        D::to_bytes_extend(&self.data.as_ref(), v);
    }
}

impl<D, S> HasCrossoverInsertMutation<S> for OpaquePacket<D>
where 
    D: Delimited,
    S: HasMaxSize + HasRand,
{
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        self.data.mutate_crossover_insert(state, &other.data)
    }
}

impl<D, S> HasCrossoverReplaceMutation<S> for OpaquePacket<D>
where
    D: Delimited,
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, libafl::Error> {
        self.data.mutate_crossover_replace(state, &other.data)
    }
}

impl<D, S> HasSpliceMutation<S> for OpaquePacket<D>
where
    D: Delimited,
    S: HasRand + HasMaxSize,
{
    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, libafl::Error> {
        self.data.mutate_splice(state, &other.data)
    }
}

impl<D, MT, S> HasHavocMutation<MT, S> for OpaquePacket<D>
where
    D: Delimited,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{ 
    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: MutationId) -> Result<MutationResult, libafl::Error> {
        self.data.mutate_havoc(state, mutations, mutation)
    }
}

/// Protocols that use this delimiter:
/// - FTP
#[derive(Clone, Debug, Default, Hash)]
pub struct CrlfDelim;

impl Delimited for CrlfDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else {
            v.extend(data);
            v.extend(b"\r\n");
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        subslice_idx(b"\r\n", data).map(|idx| idx + 2)
    }
}

/// Protocols that use this delimiter:
/// - FTP
#[derive(Clone, Debug, Default, Hash)]
pub struct RedisDelim;

impl Delimited for RedisDelim {
    // From the docs:
    //
    // "Clients send commands to a Redis server as an array of bulk strings.
    // The first (and sometimes also the second) bulk string in the array is the
    // command's name. Subsequent elements of the array are the arguments for
    // the command."
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else {
            let mut curr_idx: usize = if matches!(data.get(0), Some(b'$')) { 1 } else { 0 };
            let Some(crlf1_end) = subslice_idx(b"\r\n", &data[curr_idx..]).map(|l| l + 2) else {
                v.extend(b"*0\r\n");
                return
            };

            curr_idx += crlf1_end;

            let mut pkt_indices = Vec::new();
            loop {
                let Some(crlf1_end) = subslice_idx(b"\r\n", &data[curr_idx..]).map(|l| l + 2) else {
                    pkt_indices.push((curr_idx, data.len() - curr_idx));
                    break
                };

                curr_idx += crlf1_end;
                let Some(crlf2_end) = subslice_idx(b"\r\n", &data[curr_idx..]).map(|l| l + 2) else {
                    pkt_indices.push((curr_idx, data.len() - curr_idx));
                    break
                };

                pkt_indices.push((curr_idx, crlf2_end - 2));
                curr_idx += crlf2_end;
            }

            let array_num = cmp::min(pkt_indices.len(), 512);
            v.push(b'*');
            v.extend(array_num.to_string().as_bytes());
            v.extend(b"\r\n");
            for (start, len) in pkt_indices.into_iter().take(512) {
                v.push(b'$');
                v.extend(len.to_string().as_bytes());
                v.extend(b"\r\n");
                v.extend(&data[start..start + len]);
                v.extend(b"\r\n");
            }
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        // Array of complex strings
        data.get(0).filter(|b| **b == b'*')?;
        let arr_length_end = subslice_idx(b"\r\n", &data[1..])?;
        let mut arr_len = 0usize;
        for &i in &data[1..1 + arr_length_end] {
            if i >= b'0' && i <= b'9' {
                arr_len = arr_len.checked_mul(10)?;
                arr_len = arr_len.checked_add((i - b'0') as usize)?;
            } else {
                return None
            }
        }


        if arr_length_end == 0 || arr_len > 512 {
            return None
        }

        let mut curr_idx = 3 + arr_length_end;
        'arr_elems: for _ in 0..arr_len {
            data.get(curr_idx).filter(|b| **b == b'$')?;
            // Consume dollar symbol
            curr_idx += 1;
            let length_end = subslice_idx(b"\r\n", &data[curr_idx..])?;
            let mut content_len = 0usize;
            for &i in &data[curr_idx..curr_idx + length_end] {
                if i >= b'0' && i <= b'9' {
                    content_len = content_len.checked_mul(10)?;
                    content_len = content_len.checked_add((i - b'0') as usize)?;
                } else if i == b'-' && length_end == 2 && data[curr_idx + 1] == b'1' {
                    curr_idx += 4; // "Null" data type `$-1\r\n`
                    continue 'arr_elems
                } else {
                    return None
                }
            }


            // Consume length field and CRLF
            curr_idx += length_end + 2;

            if (length_end == 0) || content_len > 512 * 1000 * 1000 {
                // Lengths greater than 512 MB disallowed; empty length field disallowed.
                return None
            }

            if data.len() < curr_idx + content_len + 2 || !matches!(&data[curr_idx + content_len..curr_idx + content_len + 2], b"\r\n") {
                return None
            }

            // Consume content and CRLF
            curr_idx += content_len + 2;
        }

        Some(curr_idx)
    }
}

/// Protocols that use this delimiter:
/// - DAAP
/// - RTSP
/// - SIP
/// 
/// NOTE: requests that contain bodies may not work with this.
#[derive(Clone, Debug, Default, Hash)]
pub struct HttpDelim;

impl Delimited for HttpDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        let content_len_str = b"Content-Length:";
        
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else {
            if let Some(idx) = subslice_idx(b"\r\n\r\n", data) {
                let content_len = data.len() - idx;

                if let Some(content_len_idx) = subslice_idx(content_len_str, &data[..idx]).map(|i| i + content_len_str.len()) {
                    let content_len_end = subslice_idx(b"\r\n", &data[content_len_idx..]).unwrap();

                    // Insert the correct Content-Length value
                    v.extend(&data[..content_len_idx]);
                    v.push(b' ');
                    v.extend(content_len.to_string().as_bytes());
                    v.extend(&data[content_len_end..]);
                } else {
                    v.extend(data);
                };
            } else {
                if let Some(content_len_idx) = subslice_idx(content_len_str, data).map(|i| i + content_len_str.len()) {
                    let content_len_end = subslice_idx(b"\r\n", &data[content_len_idx..]).unwrap_or(data.len());
                    v.extend(&data[..content_len_idx]);
                    v.push(b' ');
                    v.push(b'0');
                    v.extend(&data[content_len_end..]);
                    v.extend(b"\r\n\r\n");
                } else {
                    v.extend(data);
                    v.extend(b"\r\n\r\n");
                };
            }
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        subslice_idx(b"\r\n\r\n", data)
            .map(|idx| idx + 4)
            .and_then(|idx| {
                let content_len = b"Content-Length:";
                if let Some(content_len_idx) = subslice_idx(content_len, &data[..idx]) {
                    let content_len_end = subslice_idx(b"\r\n", &data[content_len_idx..])?;
                    let mut content_len = 0usize;
                    for &i in data[content_len_idx..content_len_idx + content_len_end].trim_ascii() {
                        if i >= b'0' && i <= b'9' {
                            content_len = content_len.checked_mul(10)?;
                            content_len = content_len.checked_add((i - b'0') as usize)?;
                        } else {
                            break
                        }
                    }

                    Some(idx + content_len)
                } else {
                    Some(idx)
                }
            })
    }
}

fn subslice_idx(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Protocols that use this delimiter:
/// - DTLS 1.2
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct Dtls12Delim;

impl Delimited for Dtls12Delim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else if data.len() <= 13 {
            v.extend(data.iter().take(11).chain(std::iter::repeat(&0u8).take(11usize.saturating_sub(data.len()))));
            v.extend(0u16.to_be_bytes());
        } else {
            let payload_len = (data.len() - 13) as u16;
            v.extend(&data[..11]);
            v.extend(payload_len.to_be_bytes());
            v.extend(&data[13..]);
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if data.len() < 13 {
            return None
        }

        let length = u16::from_be_bytes(data[11..13].try_into().unwrap()) as usize + 13;
        if length > data.len() {
            None
        } else {
            Some(length)
        }
    }
}

/// Protocols that use this delimiter:
/// - DICOM
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct DicomDelim;

impl Delimited for DicomDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else if data.len() <= 6 {
            v.extend([0u8; 6]);
        } else {
            let packet_len = (data.len() - 6) as u32;
            v.extend(&data[..2]);
            v.extend(packet_len.to_be_bytes());
            v.extend(&data[6..]);
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if data.len() < 6 {
            return None
        }

        let packet_length = u32::from_be_bytes(data[2..6].try_into().unwrap()) as usize + 6;

        if packet_length > data.len() {
            None
        } else {
            Some(packet_length)
        }
    }
}

/// Protocols that use this delimiter:
/// - MariaDB
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct MysqlDelim;

impl Delimited for MysqlDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else {
            let sqn = *data.get(3).unwrap_or(&0);
            let data = data.get(4..).unwrap_or(&[]);
            let data_len = cmp::min(data.len(), 0x_ff_ff_ff);
            let data_bytes = &data_len.to_le_bytes()[..3];
            v.extend(data_bytes);
            v.push(sqn);
            v.extend(&data[..data_len]);
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if data.len() < 4 {
            return None
        }

        let mut packet_length = 0usize;
        for i in 0..3 {
            packet_length *= 10;
            packet_length += data[2 - i] as usize;
        }

        if 4 + packet_length > data.len() {
            None
        } else {
            Some(4 + packet_length)
        }
    }
}

/// Protocols that use this delimiter:
/// - Exim
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct EximDelim;

impl Delimited for EximDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(idx) = Self::delimit(data) {
            v.extend(&data[..idx]);
        } else if let Some(b"DATA") = data.get(..4) {
            v.extend(data);
            v.extend(b"\r\n.\r\n");
        } else {
            v.extend(data);
            v.extend(b"\r\n");
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if let Some(b"DATA") = data.get(..4) {
            subslice_idx(b"\r\n.\r\n", data).map(|idx| idx + 5)
        } else if let Some(idx) = subslice_idx(b"\r\n", data) {
            Some(idx + 2)
        } else {
            None
        }
    }
}

/// Protocols that use this delimiter:
/// - SSH
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct SshDelim;

impl Delimited for SshDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(delim) = Self::delimit(data) {
            v.extend(&data[..delim]);
        } else if let Some(b"SSH-") = data.get(..4) {
            v.extend(data);
            v.extend(b"\r\n");
        } else if data.len() <= 6 {
            v.extend(4u32.to_be_bytes());
            v.push(2);
            v.push(20);
            v.extend([0u8; 2]);
        } else {
            let mut message_code = data[5];
            let mut recorded_len = data.len() as u32 - 4;
            if message_code < 20 || message_code > 49 {
                if recorded_len < 8 {
                    message_code = 20 + (message_code % 30);
                } else {
                    recorded_len -= 8;
                }
            }

            v.extend(recorded_len.to_be_bytes());
            v.push(data[4]);
            v.push(message_code);
            v.extend(&data[6..]);
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if let Some(b"SSH-") = &data.get(..4) {
            subslice_idx(b"\r\n", data).map(|idx| idx + 2)
        } else if data.len() < 6 {
            None
        } else {
            let mut len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize + 4;
            let message_code = data[5];

            if message_code < 20 || message_code > 49 {
                len += 8;
            }

            if len > data.len() {
                None
            } else {
                Some(len)
            }
        }
    }
}

/// Protocols that use this delimiter:
/// - SSL
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct SslDelim;

impl Delimited for SslDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(delim) = Self::delimit(data) {
            v.extend(&data[..delim]);
        } else if data.len() < 5 {
            v.extend(data.iter().take(3).chain(std::iter::repeat(&0u8).take(3usize.saturating_sub(data.len()))));
            v.extend(0u16.to_be_bytes());
        } else {
            let fixed_len = u16::try_from(data.len() - 5).unwrap_or(u16::MAX);
            v.extend(&data[..3]);
            v.extend(fixed_len.to_be_bytes());
            v.extend(&data[5..5 + fixed_len as usize]);
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        if data.len() < 5 {
            None
        } else {
            let len = u16::from_be_bytes(data[3..5].try_into().unwrap()) as usize + 5;
            if len > data.len() {
                return None
            } else {
                Some(len)
            }
        }
    }
}

/// Protocols that use this delimiter:
/// - DNS
/// 
#[derive(Clone, Debug, Default, Hash)]
pub struct DnsDelim;

impl Delimited for DnsDelim {
    fn to_bytes_extend(data: &[u8], v: &mut Vec<u8>) {
        if let Some(delim) = dns_len(data) {
            v.extend((delim as u16).to_be_bytes());
            v.extend(&data[2..delim]);
        } else {
            if data.len() == 1 {
                v.extend(data);
            } else {
                let data_len = cmp::min(data.len(), u16::MAX as usize);
                v.extend((data_len as u16).to_be_bytes());
                v.extend(data.get(2..data_len).unwrap_or(&[]));
            }
        }
    }

    fn delimit(data: &[u8]) -> Option<usize> {
        // We co-opt the ident field of the DNS query to record the query length
        if data.is_empty() {
            None
        } else if data.len() < 2 {
            Some(data.len())
        } else {
            let len = u16::from_be_bytes(data[..2].try_into().unwrap()) as usize;
            if len > data.len() {
                None
            } else {
                Some(len)
            }
        }
    }
}

fn dns_len(data: &[u8]) -> Option<usize> {
    if data.len() < 12 {
        return None
    }

    let qdcount = u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize;
    let ancount = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let nscount = u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize;
    let arcount = u16::from_be_bytes(data[10..12].try_into().unwrap()) as usize;

    let mut idx = 12;

    for _ in 0..qdcount {
        loop {
            match data.get(idx)? {
                0 => {
                    idx += 1;
                    break
                }
                0b_1100_0000.. => {
                    idx += 2;
                    break
                }
                l => {
                    idx += *l as usize + 1;
                }
            }
        }

        idx += 4; // qtype, qclass
    }

    for _ in 0..ancount + nscount + arcount {
        loop {
            match data.get(idx)? {
                0 => {
                    idx += 1;
                    break
                }
                0b_1100_0000.. => {
                    idx += 2;
                    break
                }
                l => {
                    idx += *l as usize + 1;
                }
            }
        }

        idx += 8; // qtype, qclass, ttl

        let rdlength = u16::from_be_bytes(data.get(idx..idx + 2)?.try_into().unwrap()) as usize;
        idx += 2; // rdlength field
        idx += rdlength; // rdata field
    }

    if idx > data.len() {
        None
    } else {
        Some(idx)
    }
}


