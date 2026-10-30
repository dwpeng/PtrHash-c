//! C API for PtrHash.
//!
//! This module exports a small `extern "C"` interface so that the crate can be
//! linked from C/C++ as a `cdylib`. The corresponding header is
//! [`include/ptr_hash.h`](../include/ptr_hash.h).
//!
//! The API is intentionally small: build an immutable MPH[F] from `u64` keys or
//! from byte strings, query it (individually or in batches), and free it.
//! Construction is fallible; querying is not (invalid handles return
//! `PTR_HASH_INDEX_INVALID`).

#![allow(non_camel_case_types)]

use crate::hash::Xxh3_128;
use crate::{CompactPtrHash, DefaultPtrHash, FastPtrHash, PtrHashParams};
use std::cell::RefCell;
use std::ffi::{CString, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;

/// Maximum number of keys supported by PtrHash.
const MAX_KEYS: u64 = 1 << 40;

/// Returned by the query functions when the handle is invalid or when a
/// byte-string handle is queried with an integer key (or vice versa).
pub const PTR_HASH_INDEX_INVALID: u64 = u64::MAX;

const VARIANT_DEFAULT: c_int = 0;
const VARIANT_FAST: c_int = 1;
const VARIANT_COMPACT: c_int = 2;

const BATCH_CHUNK: usize = 16;

/// Status code returned by fallible C API functions.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ptr_hash_status {
    PTR_HASH_OK = 0,
    PTR_HASH_ERR_INVALID_ARGUMENT = 1,
    PTR_HASH_ERR_CONSTRUCTION_FAILED = 2,
    PTR_HASH_ERR_PANIC = 3,
}

enum U64Mphf {
    Default(DefaultPtrHash),
    Fast(FastPtrHash),
    Compact(CompactPtrHash),
}

type BytesDefault = DefaultPtrHash<Xxh3_128, &'static [u8]>;
type BytesFast = FastPtrHash<Xxh3_128, &'static [u8]>;
type BytesCompact = CompactPtrHash<Xxh3_128, &'static [u8]>;

enum BytesMphf {
    Default(BytesDefault),
    Fast(BytesFast),
    Compact(BytesCompact),
}

enum Inner {
    U64(U64Mphf),
    Bytes(BytesMphf),
}

/// Opaque handle exposed to C as `ptr_hash_t`.
pub struct ptr_hash_t {
    inner: Inner,
}

struct BuildError {
    status: ptr_hash_status,
    message: String,
}

impl BuildError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: ptr_hash_status::PTR_HASH_ERR_INVALID_ARGUMENT,
            message: message.into(),
        }
    }

    fn construction(variant: &str) -> Self {
        Self {
            status: ptr_hash_status::PTR_HASH_ERR_CONSTRUCTION_FAILED,
            message: format!(
                "PtrHash construction failed for the {variant} variant; \
                 try a stronger hash function or different keys"
            ),
        }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_last_error(message: &str) {
    let sanitized = message.replace('\0', " ");
    LAST_ERROR.with(|slot| *slot.borrow_mut() = CString::new(sanitized).unwrap());
}

fn set_status(status: *mut ptr_hash_status, value: ptr_hash_status) {
    if !status.is_null() {
        unsafe { *status = value };
    }
}

fn finish_build(
    result: Result<Result<ptr_hash_t, BuildError>, Box<dyn std::any::Any + Send>>,
    status: *mut ptr_hash_status,
) -> *mut ptr_hash_t {
    match result {
        Ok(Ok(handle)) => {
            set_last_error("");
            set_status(status, ptr_hash_status::PTR_HASH_OK);
            Box::into_raw(Box::new(handle))
        }
        Ok(Err(error)) => {
            set_last_error(&error.message);
            set_status(status, error.status);
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error("internal error: PtrHash panicked");
            set_status(status, ptr_hash_status::PTR_HASH_ERR_PANIC);
            ptr::null_mut()
        }
    }
}

fn build_u64(keys: &[u64], variant: c_int) -> Result<ptr_hash_t, BuildError> {
    let inner = match variant {
        VARIANT_DEFAULT => U64Mphf::Default(
            DefaultPtrHash::try_new(keys, PtrHashParams::default())
                .ok_or_else(|| BuildError::construction("default"))?,
        ),
        VARIANT_FAST => U64Mphf::Fast(
            FastPtrHash::try_new(keys, PtrHashParams::default())
                .ok_or_else(|| BuildError::construction("fast"))?,
        ),
        VARIANT_COMPACT => U64Mphf::Compact(
            CompactPtrHash::try_new(keys, PtrHashParams::default_compact())
                .ok_or_else(|| BuildError::construction("compact"))?,
        ),
        _ => return Err(BuildError::invalid("unknown ptr_hash_variant value")),
    };
    Ok(ptr_hash_t {
        inner: Inner::U64(inner),
    })
}

fn build_bytes(keys: &[&'static [u8]], variant: c_int) -> Result<ptr_hash_t, BuildError> {
    let inner = match variant {
        VARIANT_DEFAULT => BytesMphf::Default(
            BytesDefault::try_new(keys, PtrHashParams::default())
                .ok_or_else(|| BuildError::construction("default"))?,
        ),
        VARIANT_FAST => BytesMphf::Fast(
            BytesFast::try_new(keys, PtrHashParams::default())
                .ok_or_else(|| BuildError::construction("fast"))?,
        ),
        VARIANT_COMPACT => BytesMphf::Compact(
            BytesCompact::try_new(keys, PtrHashParams::default_compact())
                .ok_or_else(|| BuildError::construction("compact"))?,
        ),
        _ => return Err(BuildError::invalid("unknown ptr_hash_variant value")),
    };
    Ok(ptr_hash_t {
        inner: Inner::Bytes(inner),
    })
}

/// Build a borrowed byte slice from a raw pointer and length.
///
/// # Safety
///
/// If `len > 0`, `ptr` must point to `len` initialized bytes. The returned
/// reference is given an arbitrary lifetime; callers must only use it while the
/// underlying allocation is alive. PtrHash never stores key references, so the
/// build-time use is always confined to the call.
unsafe fn raw_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn check_n(n: usize) -> Result<(), BuildError> {
    if n as u64 > MAX_KEYS {
        return Err(BuildError::invalid(format!(
            "too many keys: {n} (PtrHash supports at most 2^40)"
        )));
    }
    Ok(())
}

impl ptr_hash_t {
    fn n(&self) -> usize {
        match &self.inner {
            Inner::U64(U64Mphf::Default(h)) => h.n(),
            Inner::U64(U64Mphf::Fast(h)) => h.n(),
            Inner::U64(U64Mphf::Compact(h)) => h.n(),
            Inner::Bytes(BytesMphf::Default(h)) => h.n(),
            Inner::Bytes(BytesMphf::Fast(h)) => h.n(),
            Inner::Bytes(BytesMphf::Compact(h)) => h.n(),
        }
    }

    fn max_index(&self) -> usize {
        match &self.inner {
            Inner::U64(U64Mphf::Default(h)) => h.max_index(),
            Inner::U64(U64Mphf::Fast(h)) => h.max_index(),
            Inner::U64(U64Mphf::Compact(h)) => h.max_index(),
            Inner::Bytes(BytesMphf::Default(h)) => h.max_index(),
            Inner::Bytes(BytesMphf::Fast(h)) => h.max_index(),
            Inner::Bytes(BytesMphf::Compact(h)) => h.max_index(),
        }
    }

    fn is_minimal(&self) -> bool {
        matches!(
            self.inner,
            Inner::U64(U64Mphf::Default(_) | U64Mphf::Compact(_))
                | Inner::Bytes(BytesMphf::Default(_) | BytesMphf::Compact(_))
        )
    }

    fn index_u64(&self, key: u64) -> Option<u64> {
        match &self.inner {
            Inner::U64(U64Mphf::Default(h)) => Some(h.index(&key) as u64),
            Inner::U64(U64Mphf::Fast(h)) => Some(h.index(&key) as u64),
            Inner::U64(U64Mphf::Compact(h)) => Some(h.index(&key) as u64),
            Inner::Bytes(_) => None,
        }
    }

    fn index_bytes(&self, key: &'static [u8]) -> Option<u64> {
        match &self.inner {
            Inner::Bytes(BytesMphf::Default(h)) => Some(h.index(&key) as u64),
            Inner::Bytes(BytesMphf::Fast(h)) => Some(h.index(&key) as u64),
            Inner::Bytes(BytesMphf::Compact(h)) => Some(h.index(&key) as u64),
            Inner::U64(_) => None,
        }
    }
}

macro_rules! batch_u64 {
    ($h:expr, $keys:expr, $out:expr) => {{
        for (in_chunk, out_chunk) in $keys.chunks(BATCH_CHUNK).zip($out.chunks_mut(BATCH_CHUNK)) {
            let mut batch = [0u64; BATCH_CHUNK];
            batch[..in_chunk.len()].copy_from_slice(in_chunk);
            let indices = $h.index_batch::<BATCH_CHUNK, _>(batch);
            for (dst, src) in out_chunk.iter_mut().zip(indices.iter()) {
                *dst = *src as u64;
            }
        }
    }};
}

macro_rules! batch_bytes {
    ($h:expr, $keys:expr, $out:expr) => {{
        for (in_chunk, out_chunk) in $keys.chunks(BATCH_CHUNK).zip($out.chunks_mut(BATCH_CHUNK)) {
            let mut batch: [&'static [u8]; BATCH_CHUNK] = [&[]; BATCH_CHUNK];
            batch[..in_chunk.len()].copy_from_slice(in_chunk);
            let indices = $h.index_batch::<BATCH_CHUNK, _>(batch);
            for (dst, src) in out_chunk.iter_mut().zip(indices.iter()) {
                *dst = *src as u64;
            }
        }
    }};
}

/// Return the PtrHash version as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn ptr_hash_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Return the error message for the most recent failed call on this thread.
///
/// The pointer is valid until the next failing call on the same thread.
#[unsafe(no_mangle)]
pub extern "C" fn ptr_hash_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Build a PtrHash over `n` `u64` keys.
///
/// Returns `NULL` on failure and writes the reason to `status` (when non-NULL).
/// `keys` may be NULL only when `n == 0`. The keys are copied into the hash
/// function's internal representation and need not outlive this call.
///
/// # Safety
///
/// `keys` must point to at least `n` initialized `u64` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_build_u64(
    keys: *const u64,
    n: usize,
    variant: c_int,
    status: *mut ptr_hash_status,
) -> *mut ptr_hash_t {
    let result = catch_unwind(AssertUnwindSafe(|| {
        check_n(n)?;
        if n > 0 && keys.is_null() {
            return Err(BuildError::invalid("keys is NULL but n > 0"));
        }
        let keys = if n == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(keys, n) }
        };
        build_u64(keys, variant)
    }));
    finish_build(result, status)
}

/// Build a PtrHash over `n` byte-string keys.
///
/// `keys[i]` points to `lengths[i]` bytes. Both arrays may be NULL only when
/// `n == 0`. The key bytes are hashed during this call and need not outlive it.
///
/// # Safety
///
/// `keys` and `lengths` must each point to at least `n` elements, and every
/// `keys[i]` must point to `lengths[i]` initialized bytes (unless the length is
/// zero).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_build_bytes(
    keys: *const *const u8,
    lengths: *const usize,
    n: usize,
    variant: c_int,
    status: *mut ptr_hash_status,
) -> *mut ptr_hash_t {
    let result = catch_unwind(AssertUnwindSafe(|| {
        check_n(n)?;
        if n > 0 && (keys.is_null() || lengths.is_null()) {
            return Err(BuildError::invalid("keys or lengths is NULL but n > 0"));
        }
        let key_ptrs = if n == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(keys, n) }
        };
        let lens = if n == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(lengths, n) }
        };

        let mut slices: Vec<&'static [u8]> = Vec::with_capacity(n);
        for (i, (&key, &len)) in key_ptrs.iter().zip(lens.iter()).enumerate() {
            if len > 0 && key.is_null() {
                return Err(BuildError::invalid(format!("keys[{i}] is NULL")));
            }
            slices.push(unsafe { raw_slice(key, len) });
        }
        build_bytes(&slices, variant)
    }));
    finish_build(result, status)
}

/// Free a handle returned by one of the build functions. NULL is ignored.
///
/// # Safety
///
/// `handle` must be NULL or a pointer returned by this library that has not
/// been freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_free(handle: *mut ptr_hash_t) {
    if handle.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(handle) });
}

/// Number of keys in the MPH[F].
///
/// # Safety
///
/// `handle` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_len(handle: *const ptr_hash_t) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*handle }.n()
}

/// Upper bound on the values returned by the query functions.
///
/// For the default and compact variants this equals `ptr_hash_len()`.
/// For the fast (non-minimal) variant it is roughly `1.01 * ptr_hash_len()`.
///
/// # Safety
///
/// `handle` must be a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_max_index(handle: *const ptr_hash_t) -> usize {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*handle }.max_index()
}

/// Returns 1 if the handle is a minimal PHF, 0 otherwise (including NULL).
///
/// # Safety
///
/// `handle` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_is_minimal(handle: *const ptr_hash_t) -> c_int {
    if handle.is_null() {
        return 0;
    }
    unsafe { &*handle }.is_minimal() as c_int
}

/// Look up a `u64` key.
///
/// Returns `PTR_HASH_INDEX_INVALID` if `handle` is NULL or was built from byte
/// strings.
///
/// # Safety
///
/// `handle` must be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_index_u64(handle: *const ptr_hash_t, key: u64) -> u64 {
    if handle.is_null() {
        return PTR_HASH_INDEX_INVALID;
    }
    unsafe { &*handle }
        .index_u64(key)
        .unwrap_or(PTR_HASH_INDEX_INVALID)
}

/// Look up a byte-string key.
///
/// Returns `PTR_HASH_INDEX_INVALID` if `handle` is NULL, if `key` is NULL with
/// `len > 0`, or if the handle was built from `u64` keys.
///
/// # Safety
///
/// If `len > 0`, `key` must point to `len` initialized bytes. `handle` must be
/// NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_index_bytes(
    handle: *const ptr_hash_t,
    key: *const u8,
    len: usize,
) -> u64 {
    if handle.is_null() || (len > 0 && key.is_null()) {
        return PTR_HASH_INDEX_INVALID;
    }
    let key = unsafe { raw_slice(key, len) };
    unsafe { &*handle }
        .index_bytes(key)
        .unwrap_or(PTR_HASH_INDEX_INVALID)
}

/// Look up `n` `u64` keys and write the results to `out`.
///
/// Returns `n` on success and `(size_t)-1` on error. The handle must have been
/// built from `u64` keys.
///
/// # Safety
///
/// `keys` and `out` must each point to at least `n` elements. `handle` must be
/// NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_index_batch_u64(
    handle: *const ptr_hash_t,
    keys: *const u64,
    n: usize,
    out: *mut u64,
) -> usize {
    if handle.is_null() || (n > 0 && (keys.is_null() || out.is_null())) {
        return usize::MAX;
    }
    if n == 0 {
        return 0;
    }
    let handle = unsafe { &*handle };
    let keys = unsafe { slice::from_raw_parts(keys, n) };
    let out = unsafe { slice::from_raw_parts_mut(out, n) };

    match &handle.inner {
        Inner::U64(U64Mphf::Default(h)) => batch_u64!(h, keys, out),
        Inner::U64(U64Mphf::Fast(h)) => batch_u64!(h, keys, out),
        Inner::U64(U64Mphf::Compact(h)) => batch_u64!(h, keys, out),
        Inner::Bytes(_) => return usize::MAX,
    }
    n
}

/// Look up `n` byte-string keys and write the results to `out`.
///
/// Returns `n` on success and `(size_t)-1` on error. The handle must have been
/// built from byte-string keys.
///
/// # Safety
///
/// `keys`, `lengths`, and `out` must each point to at least `n` elements, and
/// every `keys[i]` must point to `lengths[i]` initialized bytes. `handle` must
/// be NULL or a valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ptr_hash_index_batch_bytes(
    handle: *const ptr_hash_t,
    keys: *const *const u8,
    lengths: *const usize,
    n: usize,
    out: *mut u64,
) -> usize {
    if handle.is_null() || (n > 0 && (keys.is_null() || lengths.is_null() || out.is_null())) {
        return usize::MAX;
    }
    if n == 0 {
        return 0;
    }
    let handle = unsafe { &*handle };
    let key_ptrs = unsafe { slice::from_raw_parts(keys, n) };
    let lens = unsafe { slice::from_raw_parts(lengths, n) };
    let out = unsafe { slice::from_raw_parts_mut(out, n) };

    let mut slices: Vec<&'static [u8]> = Vec::with_capacity(n);
    for (i, (&key, &len)) in key_ptrs.iter().zip(lens.iter()).enumerate() {
        if len > 0 && key.is_null() {
            set_last_error(&format!("keys[{i}] is NULL"));
            return usize::MAX;
        }
        slices.push(unsafe { raw_slice(key, len) });
    }

    match &handle.inner {
        Inner::Bytes(BytesMphf::Default(h)) => batch_bytes!(h, slices, out),
        Inner::Bytes(BytesMphf::Fast(h)) => batch_bytes!(h, slices, out),
        Inner::Bytes(BytesMphf::Compact(h)) => batch_bytes!(h, slices, out),
        Inner::U64(_) => return usize::MAX,
    }
    n
}
