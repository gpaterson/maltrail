# rpi1b trail-store build investigation — status report

**Date:** 2026-10-18/19
**Branch:** `trail-store-cache` (fork `gpaterson/maltrail`, not upstream)
**Context:** rpi1b (Raspberry Pi 1B, 221MB RAM, no swap, budget `SU16G` SD card) needs 30min–4+
hours (never actually observed to finish) to build its 1.9M-trail store on every sensor start,
because upstream's own OOM fix (`1356dd5`, v3.5) deliberately rebuilds from `trails.csv` on every
load rather than persisting a cache, to guarantee nothing can go stale.

## What's done and validated (safe to rely on)

1. **ARM-musl time64 cross-compile fix** — `--cfg musl32_time64` + `-lgcc` in
   `sensor/.cargo/config.toml`. Unrelated toolchain bug (Rust's `libc` crate can't auto-detect a
   32-bit musl target's time ABI when cross-compiling), affects any 32-bit ARM musl build, not
   specific to this host. Confirmed fixed on both this fork and stock upstream v3.5.

2. **Persistent trail-store cache** (`sensor/src/trails/cache.rs`) — fingerprinted on
   `TRAILS_FILE` + both whitelist files (size+mtime) + `REPAIR_TRUNCATED_TRAILS`. A cache hit
   mmaps the finished tables back with zero rebuild. Closes the "cache identity omits whitelist
   and load options" gap Copilot flagged on the original (closed, rejected) PR #19641.
   Round-trip tested end to end (`load_cached_round_trips_through_a_real_cache_file_and_notices_edits`):
   fresh build → cache write → cache hit with byte-identical lookups → file edit → correct
   rebuild, not stale-served.

3. **`MALTRAIL_TRAIL_SCRATCH_DIR`** (`region.rs::scratch_dir_override`) — env var, set via the
   systemd unit's drop-in, redirects both the mmap-spill scratch files and the cache file onto a
   separate device from `TRAILS_FILE`. On rpi1b, pointed at the USB-attached log drive
   (`/mnt/usblog/scratch`) instead of the boot SD card. **Confirmed via live `/proc/diskstats`
   deltas on rpi1b**: SD card write-busy time was ~0ms in a 15s window during an active build;
   USB drive carried ~17s of cumulative write-busy time in the same window. This part
   definitively works as designed.

4. **`selftest.rs` now calls `load_cached()`, not `load_with()`** — `-T`/`ExecStartPre` used to
   never touch the cache (build twice per start, benefit from the cache written by neither run).
   Fixed; `-T` now validates exactly the store `ExecStart` is about to use.

All of the above: 44/44 `trails::` tests pass, plus one pre-existing unrelated failure elsewhere
in the suite (`config::tests::typo_heuristics...`, confirmed present on the base branch before
any of tonight's changes).

## What's investigated but NOT solved: the build itself is still slow

**Falsified hypothesis 1 — table regrowth/rehashing.** `ip4`/`ip4_port` capacity was guessed at
"~1/8 of rows," which seemed like it could be badly wrong for an IP-heavy blocklist, causing
repeated doubling (each one re-churning the whole table through mmap'd pages). Tried two fixes:
a cheap pre-scan (`scan_counts`) to get real IPv4/IPv4:port proportions, and oversizing on the
(wrong) assumption that unwritten mmap pages cost nothing. **Both reverted.** Direct instrumentation
(`MALTRAIL_TRACE_SPILL=1` env var, still in `region.rs`, logs every spill allocation's size) showed
original vs "fixed" capacity estimates produce ~200MB of total spilled bytes either way — a ~6%
difference, nowhere near enough to explain minutes-to-hours of wall time. Also discovered
`EMPTY = u32::MAX` (not zero) means `Region::filled()`'s free-zero-fill optimization never applies
to slot arrays, so oversizing a table has a real, non-free cost (writing more sentinel values),
which is why the "oversize for safety" attempt made the synthetic benchmark *worse* (180s+ timeout
vs 28.9s baseline).

**Confirmed real cause 1 — scattered random-access pattern.** The arena (key text) is append-only/
sequential and flash-friendly. The hash-table slot arrays are not: `hash & mask` scatters inserts
across the whole ~100+MB slot array from the very first row, so the "hot" working set is the
entire table, immediately, for the whole build — exactly what budget flash storage (no swap on
this box, so no graceful degradation path for anonymous memory either, see below) is worst at.

**Attempted fix — bucketed/partitioned insert** (`loader.rs::Buckets`, committed this session).
Defers the actual `insert_prepared` call, partitioning rows into ~10MB buckets by the same bits
`hash & mask` uses for the first probe, so each bucket's replay only touches one contiguous slice
of the table at a time. Preserves pair-interning order and regex group numbering (unaffected,
still happen in original file order before a row reaches `Buckets::write`) and duplicate
resolution (same key always hashes to same bucket, so within-bucket order is still file order).
**Verified correct** (all 44 tests pass, including the two parity tests most likely to catch an
ordering bug). **NOT verified to fix the real problem**: under the harsh synthetic benchmark
(120M memory cap, 3M/s throttled I/O, 1.9M trails) this now gets **OOM-killed in ~12s**, a
different failure mode than before (previously: 180s+ timeout, no kill).

**Newly surfaced problem — dirty-page generation rate vs. throttled writeback rate.** Current
best explanation: the partition phase writes ~100MB of bucket-file data with no deliberate
pacing. Under a 3MB/s I/O throttle, the kernel can't write those dirty pages back fast enough to
keep up with how fast the CPU generates them; a cgroup `memory.max` can apparently still
OOM-kill *reclaimable* (file-backed) memory if generation outpaces writeback quickly enough, even
though the design premise ("mmap'd memory costs what the box can spare, not all of it at once",
per `region.rs`'s own module doc) assumes graceful degradation rather than a hard kill. This is a
genuinely different problem from both regrowth and write-locality - it's about *rate*, not
*location* or *repetition* - and is unaddressed as of this report.

## Dead ends, confirmed closed

- **Heap-build for cold start** (no existing store to bound a reload against, so skip
  `file_backed` entirely for the first load). Directly disproven: OOM-killed in 1.37s under a
  120M cap. rpi1b's *real* available memory (checked live: `free -m` → `available: 60MB` with
  only baseline services running) is tighter than even that test cap, so this would fail worse on
  real hardware, not better. The reason isn't really "cold start vs reload" - it's that this box
  has **no swap**, so anonymous memory has a hard ceiling with zero elasticity, while file-backed
  memory has a soft one (write back, drop, re-read). Taking away the file-backing removes the
  *only* mechanism that lets this box use more logical memory than it has physically free.

- **Build the cache on peppy (fast hardware, or the real ARM binary under `qemu-arm` for
  byte-exact ABI), ship the finished cache file to rpi1b.** Technically sound (qemu-arm runs the
  literal ARM binary, no cross-arch struct-layout risk), but explicitly rejected: user wants
  rpi1b self-contained, not dependent on another machine to produce its own trail store.

- **Hardware fault theory** (buffer overruns, DMA errors). Checked `dmesg` on rpi1b for
  errors/resets/retries since boot: none. This is a performance characteristic of a budget
  (`SU16G`) SD card under sustained small random writes, not a fault condition.

## Numbers that matter for next time

- rpi1b: 221MB total RAM, **no swap**, SD card is a generic/budget `SU16G` 16GB card (not an
  A1/A2-rated card), USB log drive is a separate physical device (`/dev/sda` as of this session;
  device letters have shifted before depending on what's plugged into the hub).
- Real trail set: ~100.3MB `trails.csv`, ~1.9M rows (exact composition - IPv4 vs domain vs URL
  proportion - was never actually measured; every attempt to pull a copy for analysis was
  either aborted to avoid competing with a live build for SD I/O, or deprioritized once the
  random-access-pattern explanation was confirmed not to depend on that composition).
- Fast-hardware baseline (peppy, x86_64, ample RAM, no throttling): the full 1.9M-trail build
  takes **2.6 seconds**. The algorithm itself is fine; everything slow about this is specific to
  rpi1b's combination of tiny RAM, no swap, and slow flash storage.
- No successful full-duration completion was ever observed on real rpi1b hardware across
  multiple attempts spanning minutes to ~4 hours (killed by `TimeoutStartSec` each time, which
  was raised from 1hr to 6hr over the course of the night without ever seeing a natural
  completion).

## Suggested next steps

1. Investigate explicit pacing in the `Buckets` partition phase — e.g. periodic `fsync`/explicit
   write-rate limiting so dirty pages never accumulate far ahead of what the throttled device can
   absorb, rather than relying on the kernel's default writeback heuristics under a hard
   `memory.max`.
2. Get a real (not synthetic-benchmark) measurement of rpi1b's actual achievable random-write
   throughput on both the SD card and the USB drive, to calibrate whether bucketing + pacing can
   plausibly bring the real build under, say, 10-15 minutes, or whether this fundamentally needs
   hours regardless.
3. Once a full build DOES complete successfully once on rpi1b (by whatever means), the cache +
   `MALTRAIL_TRAIL_SCRATCH_DIR` work already validated tonight means every subsequent restart
   should be fast - that part of tonight's effort stands regardless of how the pacing question
   above resolves.
