//! Browser glue for `wasm32-unknown-unknown`: request buffers and randomness from the page.
//!
//! The page passes `tether.random(ptr, len)` as an import, backed by `crypto.getRandomValues`, and
//! returns 0 once it has filled the buffer. Requests go in through `tether_alloc`, responses come
//! back from `tether_call` as NUL-terminated strings released with `tether_free`.
#[link(wasm_import_module = "tether")]
extern "C" {
    fn random(dest: *mut u8, len: usize) -> i32;
}

fn fill(dest: &mut [u8]) -> bool {
    // SAFETY: the import writes at most `len` bytes into the buffer it is given.
    dest.is_empty() || unsafe { random(dest.as_mut_ptr(), dest.len()) } == 0
}

fn v02(dest: &mut [u8]) -> Result<(), getrandom02::Error> {
    fill(dest)
        .then_some(())
        .ok_or(getrandom02::Error::UNSUPPORTED)
}
getrandom02::register_custom_getrandom!(v02);

/// The getrandom 0.3 custom backend, selected by `--cfg getrandom_backend="custom"`.
/// # Safety
/// `dest` must be valid for `len` writable bytes, as getrandom guarantees.
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom03::Error> {
    // SAFETY: getrandom passes a writable buffer of `len` bytes.
    let buffer = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    fill(buffer)
        .then_some(())
        .ok_or(getrandom03::Error::UNSUPPORTED)
}

/// A request buffer of `len` bytes for the page to fill before `tether_call`.
#[no_mangle]
pub extern "C" fn tether_alloc(len: usize) -> *mut u8 {
    let mut buffer = std::mem::ManuallyDrop::new(Vec::<u8>::with_capacity(len.max(1)));
    buffer.as_mut_ptr()
}

/// Wipes and releases a buffer from `tether_alloc`.
/// # Safety
/// `ptr` must come from `tether_alloc(len)` with the same `len`, passed exactly once.
#[no_mangle]
pub unsafe extern "C" fn tether_dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the caller returns the exact allocation; zeroing covers bytes it may have written.
    unsafe {
        std::ptr::write_bytes(ptr, 0, len);
        drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
    }
}
