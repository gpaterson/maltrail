//! A persistent, fingerprint-checked cache of the built trail store.
//!
//! `region.rs`'s file-backed mappings are not a cache - they are unlinked the moment they are
//! created, precisely so a fresh build can never read stale data back. This module is the thing
//! that mapping scheme deliberately does not do: write the finished store to a NAMED file next
//! to `TRAILS_FILE`, and on the next load, if nothing the store depends on has changed, mmap it
//! straight back instead of re-parsing a 100 MB CSV and rebuilding every hash table from
//! scratch.
//!
//! That rebuild is cheap on the hardware this was designed for. It is not cheap everywhere - on
//! a Raspberry Pi 1B's SD card it can run past an hour, and every unplanned sensor restart
//! (crash, reboot, a dependency not mounting in time) pays it again. This is a fork-only
//! addition for exactly that box: it is not part of the upstream design, and upstream's own
//! reasoning for rebuilding every time ("nothing can go stale") is sound for the common case.
//! What this adds is a fingerprint over everything the store's CONTENT depends on - `TRAILS_FILE`,
//! both whitelist files, and the one `LoadOptions` flag that changes what gets loaded - so a
//! cache that no longer matches its inputs is rebuilt, not served.
//!
//! # File layout
//!
//! ```text
//! [ magic: 8 bytes ]
//! [ Fingerprint, fixed size ]
//! [ scalars: masks/lens for each table, fixed size ]
//! [ section table: (offset, len) in bytes, one pair per Section, fixed size ]
//! [ -- padding to the next 8-byte boundary -- ]
//! [ section bytes, back to back, each one already a multiple of 8 bytes long ]
//! ```
//!
//! Every section referenced by `Region::from_cache_slice` starts 8-byte aligned (the largest
//! alignment any `Pod` type here needs); the three small, non-mmapped blobs (`pairs`, `ip6_port`,
//! `regex`) do not need that and are packed in immediately after.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::region::CacheFile;

const MAGIC: &[u8; 8] = b"MTRLTRC1";

/// A `(size, mtime)` pair cheap enough to check on every startup with one `stat(2)`, and exact
/// enough that any edit to the file changes it. See the module doc for why this, not a content
/// hash: `update_trails()` always rewrites and atomically renames `TRAILS_FILE`, even when the
/// result is byte-identical, so its mtime already changes on every scheduled update regardless -
/// hashing a 100 MB file to maybe skip a rebuild that happens anyway most of the time buys
/// nothing. The whitelist files are the opposite case: operator-edited, so mtime only moves when
/// their content actually does.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct FileStamp {
    size: u64,
    mtime_secs: i64,
    mtime_nanos: u32,
}

impl FileStamp {
    fn of(path: &Path) -> Option<FileStamp> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let (secs, nanos) = match modified.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            // A file genuinely timestamped before 1970 (unusual, but not impossible with a
            // corrupted clock) still gets a stable, distinct stamp rather than failing the whole
            // cache lookup.
            Err(e) => (-(e.duration().as_secs() as i64), e.duration().subsec_nanos()),
        };
        Some(FileStamp { size: meta.len(), mtime_secs: secs, mtime_nanos: nanos })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.mtime_secs.to_le_bytes());
        out.extend_from_slice(&self.mtime_nanos.to_le_bytes());
    }

    fn read(r: &mut Cursor) -> FileStamp {
        FileStamp { size: r.u64(), mtime_secs: r.i64(), mtime_nanos: r.u32() }
    }
}

/// Everything the cached store's CONTENT depends on. Two loads with equal fingerprints are
/// guaranteed to build byte-identical stores - not merely "probably the same file".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint {
    trails: FileStamp,
    whitelist: FileStamp,
    user_whitelist: Option<FileStamp>,
    repair_truncated_trails: bool,
}

impl Fingerprint {
    /// `None` when any required input cannot be stat'd (missing `TRAILS_FILE`, for instance) -
    /// the caller falls back to a fresh build either way, so there is nothing a missing
    /// fingerprint needs to report beyond "do not trust any cache".
    pub fn compute(root: &Path, trails_file: &Path, user_whitelist: Option<&Path>, repair_truncated_trails: bool) -> Option<Fingerprint> {
        let trails = FileStamp::of(trails_file)?;
        let whitelist = FileStamp::of(&root.join("data").join("whitelist.txt"))?;
        let user_whitelist = match user_whitelist {
            Some(p) => Some(FileStamp::of(p)?),
            None => None,
        };
        Some(Fingerprint { trails, whitelist, user_whitelist, repair_truncated_trails })
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.trails.write(out);
        self.whitelist.write(out);
        out.push(self.user_whitelist.is_some() as u8);
        self.user_whitelist.unwrap_or_default().write(out);
        out.push(self.repair_truncated_trails as u8);
    }

    fn read(r: &mut Cursor) -> Fingerprint {
        let trails = FileStamp::read(r);
        let whitelist = FileStamp::read(r);
        let has_user_wl = r.u8() != 0;
        let user_whitelist_stamp = FileStamp::read(r);
        let user_whitelist = has_user_wl.then_some(user_whitelist_stamp);
        let repair_truncated_trails = r.u8() != 0;
        Fingerprint { trails, whitelist, user_whitelist, repair_truncated_trails }
    }
}

/// Where the cache file lives: next to `TRAILS_FILE`, never on a separately-mounted log volume -
/// this is working state, not evidence, and does not belong under whatever retention/off-box
/// shipping policy `LOG_DIR` has.
pub fn cache_path(trails_file: &Path) -> PathBuf {
    let mut name = trails_file.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".cache");
    match super::region::scratch_dir_override() {
        // Same device as the mmap-spill scratch files chose (`MALTRAIL_TRAIL_SCRATCH_DIR`) - see
        // that function's doc for why a box might set this at all.
        Some(dir) => dir.join(name),
        None => trails_file.with_file_name(name),
    }
}

/// One of the sections written after the header, in the fixed order both sides use.
#[derive(Clone, Copy)]
enum Section {
    Arena,
    StrSlots,
    StrFilter,
    Ip4Slots,
    Ip4Filter,
    Ip4PortSlots,
    Ip4PortFilter,
    Ip6Slots,
    Ip6Filter,
    Ip6Port,
    Pairs,
    Regex,
}

const SECTIONS: [Section; 12] = [
    Section::Arena,
    Section::StrSlots,
    Section::StrFilter,
    Section::Ip4Slots,
    Section::Ip4Filter,
    Section::Ip4PortSlots,
    Section::Ip4PortFilter,
    Section::Ip6Slots,
    Section::Ip6Filter,
    Section::Ip6Port,
    Section::Pairs,
    Section::Regex,
];

/// Offsets and byte lengths for every section, plus the small scalars that do not earn one.
pub struct Layout {
    pub str_mask: usize,
    pub str_len: usize,
    pub ip4_mask: usize,
    pub ip4_len: usize,
    pub ip4_port_mask: usize,
    pub ip4_port_len: usize,
    pub ip6_mask: usize,
    pub ip6_len: usize,
    pub total_len: usize,
    /// `LoadStats` from the build that produced this cache, so a cache HIT reports the same
    /// "[i] N trails loaded" diagnostics a fresh build would have - these are not derivable from
    /// the tables alone (`loaded` counts rows, including ones a later duplicate overwrote;
    /// `total_len` is the distinct-key count `TrailDb::len()` reports).
    pub stats_rows: usize,
    pub stats_loaded: usize,
    pub stats_whitelisted: usize,
    pub stats_malformed: usize,
    offsets: [(usize, usize); SECTIONS.len()],
}

impl Layout {
    fn section(&self, s: Section) -> (usize, usize) {
        self.offsets[s as usize]
    }
}

// `Section` as a plain index into `offsets` - declared once here so `SECTIONS` and `Layout`
// cannot drift apart.
impl Section {
    const fn index(self) -> usize {
        self as usize
    }
}

impl std::ops::Index<Section> for [(usize, usize); SECTIONS.len()] {
    type Output = (usize, usize);
    fn index(&self, s: Section) -> &(usize, usize) {
        &self[s.index()]
    }
}

/// A byte buffer being built up: the header and scalars go in directly, every section is
/// appended with `push_section` (which pads to 8 bytes first and records where it landed).
struct Builder {
    out: Vec<u8>,
    offsets: Vec<(usize, usize)>,
}

impl Builder {
    fn new() -> Builder {
        Builder { out: Vec::new(), offsets: Vec::new() }
    }

    fn pad_to_8(&mut self) {
        let rem = self.out.len() % 8;
        if rem != 0 {
            self.out.resize(self.out.len() + (8 - rem), 0);
        }
    }

    /// For the three sections that are never read back through `Region::from_cache_slice`
    /// (`Pairs`, `Ip6Port`, `Regex`) - no alignment requirement, but recorded the same way so
    /// `Layout` has one consistent place to look every offset up.
    ///
    /// Offsets are recorded relative to right AFTER the section table - not to the start of
    /// `self.out`, which also holds that table's own placeholder bytes - because that is the
    /// baseline `open()` adds them back onto (`section_area`, computed the same way on that
    /// side). Recording raw `self.out.len()` here would double-count the table's own length.
    fn push_bytes(&mut self, bytes: &[u8]) {
        let offset = self.out.len() - SECTIONS.len() * 16;
        self.out.extend_from_slice(bytes);
        self.offsets.push((offset, bytes.len()));
    }

    /// For a section `Region::from_cache_slice` will map: padded to 8 bytes first, which is
    /// enough for every `Pod` type this crate puts in a `Region` (`u8`, `u64`, `StrSlot`,
    /// `IntSlot<u32|u64|u128>` - the widest of those is 16-byte aligned, but `IntSlot<u128>`'s own
    /// size is a multiple of 16 already, so the 8-byte pad before it still lands it on a 16-byte
    /// boundary whenever the previous section's length was too).
    fn push_mapped(&mut self, bytes: &[u8]) {
        self.pad_to_8();
        self.push_bytes(bytes);
    }
}

/// A cursor over a `CacheFile`'s bytes, for the header/scalars and the three small blobs that
/// are read directly rather than mapped.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    fn usize(&mut self) -> usize {
        self.u64() as usize
    }
}

/// Everything `mod.rs` needs to hand this module to write a cache file: the already-built
/// table's raw pieces, borrowed, plus the two scalars (`ip6`/overall `len`) that have no `Region`
/// of their own to carry them.
pub struct WriteParts<'a> {
    pub arena: &'a [u8],
    pub str_slots: &'a [u8],
    pub str_filter: &'a [u64],
    pub str_mask: usize,
    pub str_len: usize,
    pub ip4_slots: &'a [u8],
    pub ip4_filter: &'a [u64],
    pub ip4_mask: usize,
    pub ip4_len: usize,
    pub ip4_port_slots: &'a [u8],
    pub ip4_port_filter: &'a [u64],
    pub ip4_port_mask: usize,
    pub ip4_port_len: usize,
    pub ip6_slots: &'a [u8],
    pub ip6_filter: &'a [u64],
    pub ip6_mask: usize,
    pub ip6_len: usize,
    pub ip6_port: &'a [((u128, u16), u32)],
    pub pairs: &'a [(Box<str>, Box<str>)],
    pub regex_patterns: &'a [String],
    pub regex_source: &'a str,
    pub regex_skipped: &'a [String],
    pub regex_repaired: &'a [String],
    pub regex_fancy: bool,
    pub total_len: usize,
    pub stats_rows: usize,
    pub stats_loaded: usize,
    pub stats_whitelisted: usize,
    pub stats_malformed: usize,
}

fn u64_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: `u64` has no padding and any byte pattern is valid; this is the write side only,
    // so there is no alignment requirement on the result.
    unsafe { std::slice::from_raw_parts(words.as_ptr() as *const u8, std::mem::size_of_val(words)) }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn write_strings(out: &mut Vec<u8>, items: &[String]) {
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for s in items {
        write_string(out, s);
    }
}

fn read_string(r: &mut Cursor) -> String {
    let len = r.u32() as usize;
    String::from_utf8_lossy(r.take(len)).into_owned()
}

fn read_strings(r: &mut Cursor) -> Vec<String> {
    let n = r.u32() as usize;
    (0..n).map(|_| read_string(r)).collect()
}

/// Write a complete cache file to `path.tmp`, then atomically rename it into place - a reader
/// that races this write sees either the old cache or the whole new one, never a half-written
/// one. `path` is expected to be `cache_path(trails_file)`.
pub fn write(path: &Path, fingerprint: &Fingerprint, parts: &WriteParts) -> std::io::Result<()> {
    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    fingerprint.write(&mut header);
    for v in [
        parts.str_mask as u64,
        parts.str_len as u64,
        parts.ip4_mask as u64,
        parts.ip4_len as u64,
        parts.ip4_port_mask as u64,
        parts.ip4_port_len as u64,
        parts.ip6_mask as u64,
        parts.ip6_len as u64,
        parts.total_len as u64,
        parts.stats_rows as u64,
        parts.stats_loaded as u64,
        parts.stats_whitelisted as u64,
        parts.stats_malformed as u64,
    ] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    // The header's own length (magic + fingerprint + scalars) is not a multiple of 8, so without
    // this the padding `Builder::pad_to_8` does for each mapped section would keep every section
    // 8-byte aligned WITHIN `b.out` while still landing at a misaligned ABSOLUTE file offset,
    // once the header is prepended. Pad here instead, so `section_area` in `open()` - which this
    // length feeds into on both sides - starts at a multiple of 8 for both writer and reader.
    header.resize(header.len().next_multiple_of(8), 0);
    debug_assert_eq!(header.len(), HEADER_FIXED_LEN);

    let mut b = Builder::new();
    // The section table is a fixed number of (offset, len) pairs, living at the very start of
    // `b.out` (so right after the header in the final file). Reserve the space now and fill it
    // in once every section has actually been written, so each offset is final.
    b.out.resize(SECTIONS.len() * 16, 0);

    b.push_mapped(parts.arena);
    b.push_mapped(parts.str_slots);
    b.push_mapped(u64_bytes(parts.str_filter));
    b.push_mapped(parts.ip4_slots);
    b.push_mapped(u64_bytes(parts.ip4_filter));
    b.push_mapped(parts.ip4_port_slots);
    b.push_mapped(u64_bytes(parts.ip4_port_filter));
    b.push_mapped(parts.ip6_slots);
    b.push_mapped(u64_bytes(parts.ip6_filter));

    {
        let start = b.out.len() - SECTIONS.len() * 16;
        b.out.extend_from_slice(&(parts.ip6_port.len() as u32).to_le_bytes());
        for ((ip, port), val) in parts.ip6_port {
            b.out.extend_from_slice(&ip.to_le_bytes());
            b.out.extend_from_slice(&port.to_le_bytes());
            b.out.extend_from_slice(&val.to_le_bytes());
        }
        b.offsets.push((start, (b.out.len() - SECTIONS.len() * 16) - start));
    }
    {
        let start = b.out.len() - SECTIONS.len() * 16;
        b.out.extend_from_slice(&(parts.pairs.len() as u32).to_le_bytes());
        for (info, reference) in parts.pairs {
            write_string(&mut b.out, info);
            write_string(&mut b.out, reference);
        }
        b.offsets.push((start, (b.out.len() - SECTIONS.len() * 16) - start));
    }
    {
        let start = b.out.len() - SECTIONS.len() * 16;
        write_strings(&mut b.out, parts.regex_patterns);
        write_string(&mut b.out, parts.regex_source);
        write_strings(&mut b.out, parts.regex_skipped);
        write_strings(&mut b.out, parts.regex_repaired);
        b.out.push(parts.regex_fancy as u8);
        b.offsets.push((start, (b.out.len() - SECTIONS.len() * 16) - start));
    }

    debug_assert_eq!(b.offsets.len(), SECTIONS.len());
    let mut table = Vec::with_capacity(SECTIONS.len() * 16);
    for &(offset, len) in &b.offsets {
        // Section offsets are relative to the start of the section area (right after the
        // header+table), which is what `Layout`/`CacheFile::bytes()` both index from once the
        // two pieces are concatenated below.
        table.extend_from_slice(&(offset as u64).to_le_bytes());
        table.extend_from_slice(&(len as u64).to_le_bytes());
    }
    b.out[..table.len()].copy_from_slice(&table);

    let tmp = path.with_extension("cache.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&header)?;
        f.write_all(&b.out)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// What a successful cache open hands back: the mapping (which every `Region` built from it
/// keeps alive via its own `Arc`) and the layout needed to slice it up.
pub struct Opened {
    pub file: Arc<CacheFile>,
    pub layout: Layout,
    pub ip6_port: Vec<((u128, u16), u32)>,
    pub pairs: Vec<(Box<str>, Box<str>)>,
    pub regex_patterns: Vec<String>,
    pub regex_source: String,
    pub regex_skipped: Vec<String>,
    pub regex_repaired: Vec<String>,
    pub regex_fancy: bool,
}

/// Unpadded size of magic + fingerprint + the nine u64 scalars. `HEADER_FIXED_LEN` (what both
/// sides actually use) rounds this up to a multiple of 8 - see the padding comment in `write()`.
const HEADER_UNPADDED_LEN: usize = 8 // magic
    + (8 + 8 + 4) // trails FileStamp
    + (8 + 8 + 4) // whitelist FileStamp
    + 1 + (8 + 8 + 4) // has_user_wl + user_whitelist FileStamp
    + 1 // repair_truncated_trails
    + 8 * 13; // the thirteen u64 scalars

const HEADER_FIXED_LEN: usize = HEADER_UNPADDED_LEN.next_multiple_of(8);

/// `None` for anything that is not usable as this load's cache: wrong magic, a fingerprint that
/// does not match, a truncated file, or any other reason to distrust it. The caller's response
/// to `None` is always "build fresh", never an error - a missing or invalid cache is exactly as
/// expected the first time, or after any input changes.
pub fn open(path: &Path, want: &Fingerprint) -> Option<Opened> {
    let file = Arc::new(CacheFile::open(path).ok()?);
    let bytes = file.bytes();
    if bytes.len() < HEADER_FIXED_LEN + SECTIONS.len() * 16 {
        return None;
    }
    let mut r = Cursor::new(bytes);
    if r.take(8) != MAGIC {
        return None;
    }
    let got = Fingerprint::read(&mut r);
    if &got != want {
        return None;
    }
    let str_mask = r.usize();
    let str_len = r.usize();
    let ip4_mask = r.usize();
    let ip4_len = r.usize();
    let ip4_port_mask = r.usize();
    let ip4_port_len = r.usize();
    let ip6_mask = r.usize();
    let ip6_len = r.usize();
    let total_len = r.usize();
    let stats_rows = r.usize();
    let stats_loaded = r.usize();
    let stats_whitelisted = r.usize();
    let stats_malformed = r.usize();

    // `r.pos` is `HEADER_UNPADDED_LEN` here; the writer rounded up to `HEADER_FIXED_LEN` before
    // the section table, so the reader must skip the same padding to land on it.
    r.pos = HEADER_FIXED_LEN;
    let section_area = r.pos + SECTIONS.len() * 16;
    let mut offsets = [(0usize, 0usize); SECTIONS.len()];
    for slot in offsets.iter_mut() {
        let offset = section_area + r.usize();
        let len = r.usize();
        if offset > bytes.len() || offset + len > bytes.len() {
            return None;
        }
        *slot = (offset, len);
    }
    let layout = Layout {
        str_mask,
        str_len,
        ip4_mask,
        ip4_len,
        ip4_port_mask,
        ip4_port_len,
        ip6_mask,
        ip6_len,
        total_len,
        stats_rows,
        stats_loaded,
        stats_whitelisted,
        stats_malformed,
        offsets,
    };

    let (o, l) = layout.section(Section::Ip6Port);
    let mut pr = Cursor::new(&bytes[o..o + l]);
    let n = pr.u32() as usize;
    let mut ip6_port = Vec::with_capacity(n);
    for _ in 0..n {
        let ip = u128::from_le_bytes(pr.take(16).try_into().unwrap());
        let port = u16::from_le_bytes(pr.take(2).try_into().unwrap());
        let val = pr.u32();
        ip6_port.push(((ip, port), val));
    }

    let (o, l) = layout.section(Section::Pairs);
    let mut pr = Cursor::new(&bytes[o..o + l]);
    let n = pr.u32() as usize;
    let mut pairs = Vec::with_capacity(n);
    for _ in 0..n {
        let info = read_string(&mut pr);
        let reference = read_string(&mut pr);
        pairs.push((info.into_boxed_str(), reference.into_boxed_str()));
    }

    let (o, l) = layout.section(Section::Regex);
    let mut rr = Cursor::new(&bytes[o..o + l]);
    let regex_patterns = read_strings(&mut rr);
    let regex_source = read_string(&mut rr);
    let regex_skipped = read_strings(&mut rr);
    let regex_repaired = read_strings(&mut rr);
    let regex_fancy = rr.u8() != 0;

    Some(Opened { file, layout, ip6_port, pairs, regex_patterns, regex_source, regex_skipped, regex_repaired, regex_fancy })
}

impl Opened {
    pub fn arena(&self) -> (usize, usize) {
        self.layout.section(Section::Arena)
    }
    pub fn str_slots(&self) -> (usize, usize) {
        self.layout.section(Section::StrSlots)
    }
    pub fn str_filter(&self) -> (usize, usize) {
        self.layout.section(Section::StrFilter)
    }
    pub fn ip4_slots(&self) -> (usize, usize) {
        self.layout.section(Section::Ip4Slots)
    }
    pub fn ip4_filter(&self) -> (usize, usize) {
        self.layout.section(Section::Ip4Filter)
    }
    pub fn ip4_port_slots(&self) -> (usize, usize) {
        self.layout.section(Section::Ip4PortSlots)
    }
    pub fn ip4_port_filter(&self) -> (usize, usize) {
        self.layout.section(Section::Ip4PortFilter)
    }
    pub fn ip6_slots(&self) -> (usize, usize) {
        self.layout.section(Section::Ip6Slots)
    }
    pub fn ip6_filter(&self) -> (usize, usize) {
        self.layout.section(Section::Ip6Filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(n: u64) -> FileStamp {
        FileStamp { size: n, mtime_secs: n as i64, mtime_nanos: 0 }
    }

    #[test]
    fn fingerprint_round_trips() {
        let fp = Fingerprint {
            trails: stamp(100),
            whitelist: stamp(7),
            user_whitelist: Some(stamp(3)),
            repair_truncated_trails: true,
        };
        let mut out = Vec::new();
        fp.write(&mut out);
        let mut r = Cursor::new(&out);
        assert_eq!(Fingerprint::read(&mut r), fp);
    }

    #[test]
    fn fingerprint_without_a_user_whitelist_round_trips_too() {
        let fp = Fingerprint { trails: stamp(1), whitelist: stamp(2), user_whitelist: None, repair_truncated_trails: false };
        let mut out = Vec::new();
        fp.write(&mut out);
        let mut r = Cursor::new(&out);
        assert_eq!(Fingerprint::read(&mut r), fp);
    }

    fn empty_parts() -> WriteParts<'static> {
        WriteParts {
            arena: b"",
            str_slots: b"",
            str_filter: &[],
            str_mask: 0,
            str_len: 0,
            ip4_slots: b"",
            ip4_filter: &[],
            ip4_mask: 0,
            ip4_len: 0,
            ip4_port_slots: b"",
            ip4_port_filter: &[],
            ip4_port_mask: 0,
            ip4_port_len: 0,
            ip6_slots: b"",
            ip6_filter: &[],
            ip6_mask: 0,
            ip6_len: 0,
            ip6_port: &[],
            pairs: &[],
            regex_patterns: &[],
            regex_source: "",
            regex_skipped: &[],
            regex_repaired: &[],
            regex_fancy: false,
            total_len: 0,
            stats_rows: 0,
            stats_loaded: 0,
            stats_whitelisted: 0,
            stats_malformed: 0,
        }
    }

    #[test]
    fn a_cache_with_a_different_fingerprint_is_rejected() {
        let dir = std::env::temp_dir().join(format!("mt-cache-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv.cache");
        let written = Fingerprint { trails: stamp(1), whitelist: stamp(2), user_whitelist: None, repair_truncated_trails: true };
        write(&path, &written, &empty_parts()).unwrap();

        assert!(open(&path, &written).is_some());
        let different = Fingerprint { trails: stamp(999), ..written.clone() };
        assert!(open(&path, &different).is_none(), "a changed trails.csv must invalidate the cache");
    }

    #[test]
    fn small_blobs_round_trip_through_a_real_file() {
        let dir = std::env::temp_dir().join(format!("mt-cache-blobs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv.cache");
        let fp = Fingerprint { trails: stamp(1), whitelist: stamp(2), user_whitelist: None, repair_truncated_trails: true };

        let pairs: Vec<(Box<str>, Box<str>)> = vec![("malware (test)".into(), "(static)".into()), ("".into(), "x".into())];
        let ip6_port = vec![((0xdead_beefu128, 53u16), 7u32), ((1, 2), 3)];
        let patterns = ["evil.*\\.example".to_string()];
        let skipped = ["bad[".to_string()];
        let mut parts = empty_parts();
        parts.pairs = &pairs;
        parts.ip6_port = &ip6_port;
        parts.regex_patterns = &patterns;
        parts.regex_source = "(?P<g0>evil.*\\.example)";
        parts.regex_skipped = &skipped;
        parts.regex_fancy = true;
        write(&path, &fp, &parts).unwrap();

        let opened = open(&path, &fp).expect("must reopen with the same fingerprint");
        assert_eq!(opened.pairs, pairs);
        assert_eq!(opened.ip6_port, ip6_port);
        assert_eq!(opened.regex_patterns, vec!["evil.*\\.example".to_string()]);
        assert_eq!(opened.regex_source, "(?P<g0>evil.*\\.example)");
        assert_eq!(opened.regex_skipped, vec!["bad[".to_string()]);
        assert!(opened.regex_fancy);
        assert!(opened.regex_repaired.is_empty());
    }

    #[test]
    fn mapped_sections_round_trip_through_a_real_file() {
        let dir = std::env::temp_dir().join(format!("mt-cache-mapped-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trails.csv.cache");
        let fp = Fingerprint { trails: stamp(1), whitelist: stamp(2), user_whitelist: None, repair_truncated_trails: true };

        let arena = b"evil.example1.2.3.4".to_vec();
        let str_filter: Vec<u64> = vec![0xf0f0, 0x0f0f];
        let mut parts = empty_parts();
        parts.arena = &arena;
        parts.str_filter = &str_filter;
        parts.str_mask = 63;
        parts.str_len = 2;
        parts.total_len = 2;
        write(&path, &fp, &parts).unwrap();

        let opened = open(&path, &fp).unwrap();
        assert_eq!(opened.layout.str_mask, 63);
        assert_eq!(opened.layout.str_len, 2);
        assert_eq!(opened.layout.total_len, 2);
        let (o, l) = opened.arena();
        assert_eq!(&opened.file.bytes()[o..o + l], &arena[..]);
        let (o, l) = opened.str_filter();
        assert_eq!(o % 8, 0, "a mapped section must start 8-byte aligned");
        let got: &[u8] = &opened.file.bytes()[o..o + l];
        assert_eq!(got, u64_bytes(&str_filter));
    }
}
