#!/usr/bin/env python3
"""Helpers for running real AFLNet with the in-process transport (-N ipc://).

Formats
  delim     : { [frame] DE AD }*                        (default, -P THREAD: what the
              target reads and what AFLNet's seeds / queue files contain; the same
              format as Concat and AFLNet-pp)
  lenprefix : { [u32 BE len][frame] }*                  (-P THREAD_LENPREFIX seeds;
              the target then reads [u32 BE total] + this)
  harness   : [u32 BE total] { [u32 BE len][frame] }*   (LV format of the coverage replay,
              replayable_queue/ and the coverage scripts)
  replayable: { [u32 LE len][message] }*                (AFLNet replayable-queue/,
              each message itself in the delim / lenprefix format)

Sub-commands
  harvest        run the target once without injections and turn the frames of
                 the malicious node(s) into an AFLNet seed
  from-harness   convert harness-format (LV) seeds into AFLNet seeds
  to-harness     convert AFLNet's replayable-queue (or crashes) into harness-format
                 files named standalone_state_<ms>.bin for coverage_script_gcovr.sh
  trace          run the target on one input and print the outbox

--framing (before the sub-command) selects delim (default) or lenprefix and must
match the -P option of afl-fuzz and the harness build.
"""
import argparse
import ctypes
import os
import struct
import subprocess
import sys
import tempfile

OUTBOX_SIZE = 1024 * 1024
DIR_NAMES = {0: "REQ ", 1: "RESP", 2: "INJ "}

DELIM = b"\xde\xad"
FRAMING = "delim"   # set from --framing

# ---------------------------------------------------------------------------
# frame normalisation, identical to ipc_normalize_message[_delim]() in
# afl-fuzz.c (and, for delim, to the harness' 0xDEAD splitting)
# ---------------------------------------------------------------------------
def split_delim(m):
    frames, cur, start = [], 0, 0
    while cur + 2 <= len(m):
        if m[cur:cur + 2] == DELIM:
            frames.append(m[start:cur])
            cur += 2
            start = cur
        else:
            cur += 1
    if start < len(m):
        frames.append(m[start:])
    return frames


def split_lenprefix(m):
    frames, cur = [], 0
    while cur < len(m):
        if len(m) - cur < 4:
            f = m[cur:]
            cur = len(m)
        else:
            (l,) = struct.unpack(">I", m[cur:cur + 4])
            cur += 4
            l = min(l, len(m) - cur)
            f = m[cur:cur + l]
            cur += l
        frames.append(f)
    return frames


def normalize_message(m, max_frame=0):
    frames = split_delim(m) if FRAMING == "delim" else split_lenprefix(m)
    if max_frame:
        frames = [f[:max_frame] for f in frames]
    return [f for f in frames if f]


def frames_to_target(frames):
    """What ipc_deliver() writes for the target."""
    if FRAMING == "delim":
        return b"".join(f + DELIM for f in frames) or DELIM
    return frames_to_harness(frames)


def frames_to_harness(frames):
    body = b"".join(struct.pack(">I", len(f)) + f for f in frames)
    return struct.pack(">I", len(body)) + body


def frames_to_aflnet(frames):
    """AFLNet seed: one region per frame."""
    if FRAMING == "delim":
        return b"".join(f + DELIM for f in frames)
    return b"".join(struct.pack(">I", len(f)) + f for f in frames)


def parse_harness(data):
    if len(data) < 4:
        return []
    (total,) = struct.unpack(">I", data[:4])
    body = data[4:4 + total]
    frames, cur = [], 0
    while cur + 4 <= len(body):
        (l,) = struct.unpack(">I", body[cur:cur + 4])
        cur += 4
        if cur + l > len(body):
            break
        if l:
            frames.append(body[cur:cur + l])
        cur += l
    return frames


def parse_replayable(data):
    msgs, cur = [], 0
    while cur + 4 <= len(data):
        (l,) = struct.unpack("<I", data[cur:cur + 4])
        cur += 4
        msgs.append(data[cur:cur + l])
        cur += l
    return msgs

# ---------------------------------------------------------------------------
# running the target with an outbox (System V shm, like afl-fuzz)
# ---------------------------------------------------------------------------
libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.restype = ctypes.c_void_p
libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
libc.shmdt.argtypes = [ctypes.c_void_p]
libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_RMID = 0, 0o1000, 0o2000, 0


def run_with_outbox(target, harness_input, timeout=30):
    shm_id = libc.shmget(IPC_PRIVATE, OUTBOX_SIZE, IPC_CREAT | IPC_EXCL | 0o600)
    if shm_id < 0:
        sys.exit("shmget failed: errno %d" % ctypes.get_errno())
    try:
        addr = libc.shmat(shm_id, None, 0)
        ctypes.memset(addr, 0, 4)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(harness_input)
            path = f.name
        env = dict(os.environ, OUTBOX_SHMEM_ID=str(shm_id))
        try:
            subprocess.run([target, path], env=env, timeout=timeout,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.unlink(path)
        total = min(struct.unpack("<I", ctypes.string_at(addr, 4))[0], OUTBOX_SIZE - 4)
        body = ctypes.string_at(addr + 4, total)
        libc.shmdt(addr)
    finally:
        libc.shmctl(shm_id, IPC_RMID, None)
    entries, cur = [], 0
    while cur + 6 <= len(body):
        d, t = body[cur], body[cur + 1]
        (l,) = struct.unpack(">I", body[cur + 2:cur + 6])
        if cur + 6 + l > len(body):
            break
        entries.append((d, t, body[cur + 6:cur + 6 + l]))
        cur += 6 + l
    return entries

# ---------------------------------------------------------------------------
# sub-commands
# ---------------------------------------------------------------------------
def cmd_harvest(a):
    entries = run_with_outbox(a.target, frames_to_target([]))
    # Frames the malicious node(s) sent on their own: passed-through frames
    # (0x00) for LEADER/FED, the original frames (0x01) for BOTH.
    want = 0x01 if a.role.upper() == "BOTH" else 0x00
    frames = [p for d, _, p in entries if d == want and p]
    if a.max_frames:
        frames = frames[:a.max_frames]
    if not frames:
        sys.exit("[!] No frames harvested (is the target built for role %s?)" % a.role)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(frames_to_aflnet(frames))
    print("[+] Harvested %d frames (%d outbox entries) into %s" % (len(frames), len(entries), a.out))


def cmd_from_harness(a):
    os.makedirs(a.out_dir, exist_ok=True)
    n = 0
    for name in sorted(os.listdir(a.in_dir)):
        p = os.path.join(a.in_dir, name)
        if not os.path.isfile(p) or name.startswith("."):
            continue
        frames = parse_harness(open(p, "rb").read())
        if not frames:
            print("[!] Skipping %s (no frames)" % name)
            continue
        with open(os.path.join(a.out_dir, name), "wb") as f:
            f.write(frames_to_aflnet(frames))
        n += 1
    print("[+] Converted %d seeds into %s" % (n, a.out_dir))


def cmd_to_harness(a):
    os.makedirs(a.out_dir, exist_ok=True)
    files = [os.path.join(a.in_dir, n) for n in os.listdir(a.in_dir)
             if os.path.isfile(os.path.join(a.in_dir, n)) and not n.startswith(".") and n != "README.txt"]
    files.sort(key=lambda p: (os.stat(p).st_mtime_ns, p))
    used, n = set(), 0
    for p in files:
        data = open(p, "rb").read()
        if a.raw:
            frames = normalize_message(data, a.max_frame)
        else:
            frames = [f for m in parse_replayable(data) for f in normalize_message(m, a.max_frame)]
        if not frames:
            continue
        # Name by discovery time (ms) like AFLNet (LibAFL) does, so that
        # coverage_script_gcovr.sh can build coverage over time.
        ts = os.stat(p).st_mtime_ns // 1_000_000
        while ts in used:
            ts += 1
        used.add(ts)
        out = os.path.join(a.out_dir, "standalone_state_%d.bin" % ts)
        with open(out, "wb") as f:
            f.write(frames_to_harness(frames))
        os.utime(out, ns=(ts * 1_000_000, ts * 1_000_000))
        n += 1
    print("[+] Converted %d inputs into %s" % (n, a.out_dir))


def cmd_trace(a):
    data = open(a.input, "rb").read()
    if a.aflnet:
        frames = normalize_message(data)    # AFLNet seed / queue file
    else:
        frames = parse_harness(data)        # harness (LV) format
    for i, (d, t, p) in enumerate(run_with_outbox(a.target, frames_to_target(frames))):
        print("%4d %s type=0x%02x len=%3d" % (i, DIR_NAMES.get(d, "0x%02x" % d), t, len(p)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--framing", choices=["delim", "lenprefix"], default="delim",
                    help="AFLNet seed / target input framing (-P THREAD = delim, "
                         "-P THREAD_LENPREFIX = lenprefix; default: delim)")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("harvest")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-r", "--role", required=True, help="LEADER, FED or BOTH")
    p.add_argument("-o", "--out", required=True, help="output seed file")
    p.add_argument("-m", "--max-frames", type=int, default=0, help="keep at most N frames (0: all)")
    p.set_defaults(func=cmd_harvest)

    p = sp.add_parser("from-harness")
    p.add_argument("in_dir")
    p.add_argument("out_dir")
    p.set_defaults(func=cmd_from_harness)

    p = sp.add_parser("to-harness")
    p.add_argument("in_dir", help="AFLNet replayable-queue/ (or replayable-crashes/)")
    p.add_argument("out_dir")
    p.add_argument("--max-frame", type=int, default=0, help="same as AFLNET_IPC_MAX_FRAME")
    p.add_argument("--raw", action="store_true", help="input files are raw AFLNet queue files")
    p.set_defaults(func=cmd_to_harness)

    p = sp.add_parser("trace")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-i", "--input", required=True, help="harness-format (LV) input")
    p.add_argument("--aflnet", action="store_true", help="input is an AFLNet seed / queue file instead")
    p.set_defaults(func=cmd_trace)

    a = ap.parse_args()
    global FRAMING
    FRAMING = a.framing
    a.func(a)


if __name__ == "__main__":
    main()
