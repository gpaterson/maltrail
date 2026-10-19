//! Where the trail store's big arrays live: the heap, or a file-backed shared mapping.
//!
//! The store is ~120 MB at 1.9 M trails. On the heap that is anonymous memory, which a box without
//! swap can only get back by killing the process - on a 221 MB Raspberry Pi the kernel's OOM killer
//! did exactly that, and a reload (which builds the new store while the old one is still serving)
//! needed twice as much. In a `MAP_SHARED` mapping of a file the same bytes are page cache: the
//! kernel writes them back once and can then drop and re-read them under pressure like any other
//! file page, so the store costs what the box can spare rather than all of it at once.
//!
//! The mapping is not a cache. Every load builds a fresh store into a fresh file, which is unlinked
//! the moment it is created - nothing on disk can go stale, outlive the process, or be read by
//! the next load, so there is no question of it holding a whitelist or a trail set other than the
//! one this load was given. Space is reserved with `posix_fallocate` before anything is mapped:
//! writing a page of a sparse file on a full disk is a SIGBUS, and a sensor must not die of that.
//! Anything that fails - no directory, no space, no `mmap` - falls back to the heap, which is what
//! the store always used.

use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

/// Types a region can hold: `Copy`, no `Drop`, and every byte written before it is read (a region
/// is always created filled), so viewing mapped memory as `[T]` is sound.
///
/// # Safety
/// Implement only for plain-old-data types without padding-dependent invariants.
pub unsafe trait Pod: Copy + 'static {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u64 {}

/// Where to put file-backed regions. `None` everywhere means the heap.
#[derive(Clone)]
pub struct Spill {
    // only Linux maps; elsewhere every region is on the heap
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dir: Arc<PathBuf>,
}

/// Fork-only: redirect the build's mmap-spill scratch files AND the on-disk trail-store cache
/// (`cache.rs`) off whatever device `TRAILS_FILE` lives on, onto a separate one. Set by the
/// systemd unit's own drop-in, not `maltrail.conf` - this is a per-host storage-layout decision,
/// not something upstream's own config schema needs to carry.
///
/// Exists because `TRAILS_FILE` on a box like a Raspberry Pi 1B typically sits on the device's
/// own boot SD card, which this build hits hard (region after region of scattered small writes
/// as the hash tables grow and rehash). A box with a second, less failure-critical storage
/// device (a USB-attached drive already used for `LOG_DIR`, say) can point this there instead,
/// so a rebuild's I/O load lands on that device rather than the one everything else - including
/// the OS itself - depends on.
pub fn scratch_dir_override() -> Option<PathBuf> {
    let v = std::env::var_os("MALTRAIL_TRAIL_SCRATCH_DIR")?;
    if v.is_empty() {
        return None;
    }
    Some(PathBuf::from(v))
}

impl Spill {
    pub fn new(dir: PathBuf) -> Spill {
        Spill { dir: Arc::new(dir) }
    }

    /// Where this spill's regions live - for `loader.rs`'s `Buckets`, which keeps its own
    /// temporary files in the same place.
    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    #[cfg(target_os = "linux")]
    fn map(&self, bytes: usize) -> Option<*mut u8> {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);

        if bytes == 0 {
            return None;
        }
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        if std::env::var_os("MALTRAIL_TRACE_SPILL").is_some() {
            eprintln!("[SPILLTRACE] seq={seq} bytes={bytes}");
        }
        let name = format!(".maltrail-trails-{}-{}", std::process::id(), seq);
        let path = self.dir.join(name);
        let mut cpath = path.as_os_str().as_bytes().to_vec();
        cpath.push(0);
        unsafe {
            let fd = libc::open(
                cpath.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            );
            if fd < 0 {
                return None;
            }
            // Unlinked at once: the mapping keeps the inode alive, and nothing is left behind by
            // any way this process can end.
            libc::unlink(cpath.as_ptr() as *const libc::c_char);
            let ptr = if libc::posix_fallocate(fd, 0, bytes as libc::off_t) == 0 {
                libc::mmap(std::ptr::null_mut(), bytes, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0)
            } else {
                libc::MAP_FAILED
            };
            libc::close(fd);
            if ptr == libc::MAP_FAILED {
                None
            } else {
                Some(ptr as *mut u8)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn map(&self, _bytes: usize) -> Option<*mut u8> {
        None
    }
}

/// A whole file, mapped read-only once and shared by every [`Region`] that borrows a slice of
/// it (see `cache.rs`). One `mmap`, however many tables it backs, rather than one per table -
/// which also means there is exactly one thing to `munmap`, when the last region referencing it
/// (via its `Arc`) is gone.
///
/// `MAP_PRIVATE`, not `MAP_SHARED`: nothing in this crate ever writes through a cache mapping
/// (`TrailDb` is immutable once `finish()` returns, and the cache is only ever opened for
/// reading), but if a bug ever did, `MAP_PRIVATE` makes that a copy-on-write into process memory
/// instead of silent corruption of the cache file on disk, which every other load after this one
/// would then also read back.
pub struct CacheFile {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for CacheFile {}
unsafe impl Sync for CacheFile {}

impl CacheFile {
    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(target_os = "linux")]
    pub fn open(path: &std::path::Path) -> std::io::Result<CacheFile> {
        use std::io::ErrorKind;
        use std::os::unix::io::AsRawFd;

        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Err(std::io::Error::new(ErrorKind::InvalidData, "empty cache file"));
        }
        let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0) };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(CacheFile { ptr: ptr as *mut u8, len })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_path: &std::path::Path) -> std::io::Result<CacheFile> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "trail-store cache needs mmap (Linux only)"))
    }

    /// The raw bytes, for the header/fingerprint check before anything is reinterpreted as a
    /// table.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `ptr`/`len` map a whole, already-opened file for the lifetime of `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for CacheFile {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

enum Backing<T> {
    /// Held only to own (and eventually free) the memory `ptr` points into.
    #[allow(dead_code)]
    Heap(Vec<T>),
    // read only by the Linux unmap/msync paths; elsewhere nothing is ever mapped
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Mapped { bytes: usize },
    /// A slice of a [`CacheFile`] someone else mapped and owns. Dropping this does nothing;
    /// the mapping itself goes away only when the last `Arc<CacheFile>` pointing at it does
    /// (see `cache.rs`). `T` never appears in the variant - the slice is plain bytes, reinterpreted
    /// by `from_cache_slice` - so one mapping can back regions of different `T`.
    Borrowed(#[allow(dead_code)] Arc<CacheFile>),
}

/// A fixed-length array of `T`, on the heap or file-backed (see the module doc).
pub struct Region<T: Pod> {
    ptr: *mut T,
    len: usize,
    backing: Backing<T>,
    _marker: PhantomData<T>,
}

// The region owns its memory exclusively, exactly like the `Vec` it replaces.
unsafe impl<T: Pod + Send> Send for Region<T> {}
unsafe impl<T: Pod + Sync> Sync for Region<T> {}

impl<T: Pod> Region<T> {
    pub fn filled(len: usize, value: T, spill: Option<&Spill>) -> Region<T> {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        if let Some(raw) = spill.and_then(|s| s.map(bytes)) {
            let ptr = raw as *mut T;
            // A fresh mapping of a fallocated file reads as zeroes; writing zeroes over it would
            // only dirty every page for nothing.
            // SAFETY: viewing a `Pod` value as its bytes.
            let zero = unsafe { std::slice::from_raw_parts(&value as *const T as *const u8, std::mem::size_of::<T>()) }
                .iter()
                .all(|b| *b == 0);
            if !zero {
                // Paced the same way `loader.rs`'s `Buckets::write` paces its own writes, and for
                // the same reason: an unpaced loop dirties this whole region - tens to well over
                // a hundred MB for the big tables - as fast as the CPU can go, far faster than a
                // slow or throttled device can write it back. A cgroup `memory.max` can OOM-kill
                // that backlog outright even though the memory is nominally reclaimable, because
                // reclaimability only helps if reclaim can keep pace with allocation. `msync`'s
                // default (synchronous) mode blocks until the range is actually written, which
                // is exactly the backpressure this needs.
                const PACE_BYTES: usize = 1 << 20;
                let elem_size = std::mem::size_of::<T>().max(1);
                let pace_elems = (PACE_BYTES / elem_size).max(1);
                let mut filled_from = 0usize;
                for i in 0..len {
                    // SAFETY: `ptr` maps `len` elements, page-aligned (so aligned for any `T` here).
                    unsafe { ptr.add(i).write(value) };
                    if i + 1 - filled_from >= pace_elems || i + 1 == len {
                        #[cfg(target_os = "linux")]
                        unsafe {
                            let start = ptr.add(filled_from) as *mut libc::c_void;
                            let span = (i + 1 - filled_from) * elem_size;
                            libc::msync(start, span, libc::MS_SYNC);
                        }
                        filled_from = i + 1;
                    }
                }
            }
            return Region { ptr, len, backing: Backing::Mapped { bytes }, _marker: PhantomData };
        }
        let mut v = vec![value; len];
        let ptr = v.as_mut_ptr();
        Region { ptr, len, backing: Backing::Heap(v), _marker: PhantomData }
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self.backing, Backing::Mapped { .. })
    }

    /// A view into someone else's whole-file mapping (see [`CacheFile`]), at a byte offset the
    /// caller computed when it wrote that file. `len` elements of `T` must fit inside `file`
    /// starting at `offset`, and `offset` must already be aligned for `T` — `cache.rs` lays the
    /// file out so every region starts on a page boundary, which satisfies every `T` this module
    /// has.
    ///
    /// # Safety
    /// `offset + len * size_of::<T>() <= file.len()`, `offset` is aligned for `T`, and the bytes
    /// there really are `len` valid `T`s - which only holds for bytes this crate wrote itself in
    /// this layout. Reading someone else's file, or a shorter/older one, is instant undefined
    /// behaviour: there is no validation here, by design, because the caller just checked a
    /// fingerprint over the whole file and a torn write would have changed it.
    pub unsafe fn from_cache_slice(file: &Arc<CacheFile>, offset: usize, len: usize) -> Region<T> {
        debug_assert_eq!(offset % std::mem::align_of::<T>(), 0, "cache region misaligned for T");
        debug_assert!(offset + len * std::mem::size_of::<T>() <= file.len, "cache region out of bounds");
        let ptr = file.ptr.add(offset) as *mut T;
        Region { ptr, len, backing: Backing::Borrowed(file.clone()), _marker: PhantomData }
    }

    /// Start writing the dirty pages back now, so they are reclaimable by the time the kernel wants
    /// them rather than only after it has waited for the writeback.
    pub fn flush_async(&self) {
        #[cfg(target_os = "linux")]
        if let Backing::Mapped { bytes } = self.backing {
            unsafe { libc::msync(self.ptr as *mut libc::c_void, bytes, libc::MS_ASYNC) };
        }
    }
}

impl<T: Pod> std::ops::Deref for Region<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        // SAFETY: `ptr` points at `len` initialised elements owned by this region.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Pod> std::ops::DerefMut for Region<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as above, and `&mut self` is exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T: Pod> Drop for Region<T> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Backing::Mapped { bytes } = self.backing {
            unsafe { libc::munmap(self.ptr as *mut libc::c_void, bytes) };
        }
    }
}

/// The key-text arena: append-only bytes. File-backed, it is sized up front to an upper bound (a
/// mapped page that is never written costs nothing) and copied into a bigger region in the rare
/// case the bound was wrong.
pub enum Arena {
    Heap(Vec<u8>),
    Mapped { region: Region<u8>, used: usize, spill: Spill },
    /// A cache-loaded arena (see `cache.rs`). Exactly `region.len()` bytes, all of them real
    /// content - unlike `Mapped`, there is no `used` short of the region's own length, because
    /// `cache.rs` writes the arena at its final size and this never grows afterwards.
    Borrowed(Region<u8>),
}

impl Arena {
    pub fn with_capacity(capacity: usize, spill: Option<&Spill>) -> Arena {
        if let Some(spill) = spill {
            let region = Region::filled(capacity.max(4096), 0u8, Some(spill));
            if region.is_mapped() {
                return Arena::Mapped { region, used: 0, spill: spill.clone() };
            }
        }
        Arena::Heap(Vec::with_capacity(capacity))
    }

    /// See `Region::from_cache_slice` for the safety contract this inherits unchanged.
    pub(crate) unsafe fn from_cache(file: &std::sync::Arc<CacheFile>, offset: usize, len: usize) -> Arena {
        Arena::Borrowed(Region::from_cache_slice(file, offset, len))
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Arena::Heap(v) => v.len(),
            Arena::Mapped { used, .. } => *used,
            Arena::Borrowed(region) => region.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        match self {
            Arena::Heap(v) => v.extend_from_slice(data),
            Arena::Mapped { region, used, spill } => {
                if *used + data.len() > region.len() {
                    let mut bigger = Region::filled((region.len() * 2).max(*used + data.len()), 0u8, Some(spill));
                    bigger[..*used].copy_from_slice(&region[..*used]);
                    *region = bigger;
                }
                region[*used..*used + data.len()].copy_from_slice(data);
                *used += data.len();
            }
            Arena::Borrowed(_) => unreachable!("a cache-loaded TrailDb is immutable; nothing appends to its arena"),
        }
    }

    pub fn flush_async(&self) {
        if let Arena::Mapped { region, .. } = self {
            region.flush_async();
        }
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Arena::Mapped { .. } | Arena::Borrowed(_))
    }
}

impl std::ops::Deref for Arena {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            Arena::Heap(v) => v,
            Arena::Mapped { region, used, .. } => &region[..*used],
            Arena::Borrowed(region) => region,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::{IntTable, StrTable};
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("maltrail-region-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_cache_file_region_reads_back_what_was_written_at_its_offset() {
        let dir = scratch("cachefile");
        let path = dir.join("cache.bin");
        // Two regions packed into one file: 4 u64s at offset 0, then 3 u8s right after, at an
        // offset chosen to still be 8-byte aligned (what `cache.rs` actually guarantees for every
        // region it writes).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[11u64, 22, 33, 44].iter().flat_map(|v| v.to_ne_bytes()).collect::<Vec<u8>>());
        bytes.extend_from_slice(&[5u8, 6, 7]);
        bytes.resize(bytes.len() + (8 - bytes.len() % 8) % 8, 0); // pad to a multiple of 8
        std::fs::write(&path, &bytes).unwrap();

        let file = Arc::new(CacheFile::open(&path).unwrap());
        assert_eq!(file.len(), bytes.len());
        let ints: Region<u64> = unsafe { Region::from_cache_slice(&file, 0, 4) };
        assert_eq!(&*ints, &[11, 22, 33, 44]);
        let bytes_region: Region<u8> = unsafe { Region::from_cache_slice(&file, 32, 3) };
        assert_eq!(&*bytes_region, &[5, 6, 7]);
        // Both regions keep the SAME file mapped alive (one Arc, two clones) - dropping one must
        // not unmap it out from under the other.
        drop(ints);
        assert_eq!(&*bytes_region, &[5, 6, 7]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_region_is_file_backed_and_leaves_nothing_behind() {
        let dir = scratch("backed");
        let spill = Spill::new(dir.clone());
        let mut region = Region::filled(1 << 20, u64::MAX, Some(&spill));
        assert!(region.is_mapped(), "positive control: this must not have fallen back to the heap");
        assert!(region.iter().all(|&v| v == u64::MAX));
        region[12345] = 7;
        assert_eq!(region[12345], 7);
        // unlinked at creation, so the directory is empty while the mapping is alive
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        drop(region);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unusable_directory_falls_back_to_the_heap() {
        let spill = Spill::new(PathBuf::from("/nonexistent/maltrail/region"));
        let region = Region::filled(1000, 3u64, Some(&spill));
        assert!(!region.is_mapped());
        assert!(region.iter().all(|&v| v == 3));
    }

    /// Mapped and heap tables must answer every lookup identically - including after the slot
    /// array grew (a tiny capacity forces several rehashes into fresh mappings) and after the arena
    /// outgrew its mapped bound (a tiny hint forces the copy path).
    #[test]
    fn file_backed_tables_answer_exactly_like_heap_ones() {
        let dir = scratch("tables");
        let spill = Spill::new(dir.clone());
        let mut mapped = StrTable::with_capacity_in(4, 16, Some(&spill));
        let mut heap = StrTable::with_capacity(4, 16);
        let mut mapped4: IntTable<u32> = IntTable::with_capacity_in(4, Some(&spill));
        let mut heap4: IntTable<u32> = IntTable::with_capacity(4);
        for i in 0..50_000u32 {
            let key = format!("host{i}.example.com");
            assert_eq!(mapped.insert(&key, i), heap.insert(&key, i));
            mapped4.insert(i.wrapping_mul(2_654_435_761), i);
            heap4.insert(i.wrapping_mul(2_654_435_761), i);
        }
        // positive control: the grown table must still be file-backed (only Linux maps at all)
        assert_eq!(mapped.is_mapped(), cfg!(target_os = "linux"));
        assert_eq!(mapped.len(), heap.len());
        for i in 0..60_000u32 {
            let key = format!("host{i}.example.com");
            assert_eq!(mapped.get(&key), heap.get(&key), "{key}");
            let k = i.wrapping_mul(2_654_435_761);
            assert_eq!(mapped4.get(k), heap4.get(k));
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
