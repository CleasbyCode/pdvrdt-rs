//! Global allocator that zeroes every block before releasing it.
//!
//! flate2's miniz_oxide backend keeps plaintext in state it allocates for
//! itself -- inflate's 32 KiB history window, deflate's window and hash
//! chains -- and frees it without clearing it. There is no hook to give it
//! wiping allocation callbacks (the C++ build gives zlib wiping zalloc/zfree callbacks instead), so the
//! binary wipes at the allocator instead. This also covers the old block left
//! behind when a `Vec` grows. Cost: one memset per free, small next to the
//! compression and crypto work that produces those blocks.

use std::alloc::{GlobalAlloc, Layout};

pub struct WipeOnFree<A>(pub A);

/// glibc's explicit_bzero: a full-speed memset the compiler may not drop as a
/// dead store before the free. Does not allocate or panic.
unsafe fn bzero(ptr: *mut u8, size: usize) {
    if size != 0 {
        unsafe { libc::explicit_bzero(ptr.cast(), size) };
    }
}

/// Blocks at least this large have their whole pages discarded rather than
/// written.
const DISCARD_THRESHOLD: usize = 1 << 20;

/// Wipe `size` bytes at `ptr`.
///
/// A memset over a large block writes every page of it, including pages the
/// program reserved but never touched, so freeing a mostly-unused 1 GiB
/// buffer would briefly commit a full 1 GiB. For large blocks the whole pages
/// are instead released with MADV_DONTNEED, which drops their contents (a
/// private anonymous page reads back as zero) without touching the ones never
/// used; only the partial pages at either end are written. Any madvise
/// failure falls back to the memset.
unsafe fn wipe(ptr: *mut u8, size: usize) {
    if size >= DISCARD_THRESHOLD {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page > 0 {
            let page = page as usize;
            let start = (ptr as usize).next_multiple_of(page);
            let end = (ptr as usize + size) / page * page;
            if end > start {
                let discarded = unsafe {
                    libc::madvise(start as *mut libc::c_void, end - start, libc::MADV_DONTNEED)
                } == 0;
                if discarded {
                    unsafe {
                        bzero(ptr, start - ptr as usize);
                        bzero(end as *mut u8, ptr as usize + size - end);
                    }
                    return;
                }
            }
        }
    }
    unsafe { bzero(ptr, size) };
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            wipe(ptr, layout.size());
            self.0.dealloc(ptr, layout);
        }
    }

    // Never let the inner allocator move a block and free the old copy
    // unwiped: allocate, copy, then wipe and free the original ourselves.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return std::ptr::null_mut();
        };
        let new_ptr = unsafe { self.0.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::System;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static FREED: AtomicUsize = AtomicUsize::new(0);
    static FREED_DIRTY: AtomicBool = AtomicBool::new(false);

    /// Inner allocator that checks each block is already zero when freed.
    struct Probe;

    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.iter().any(|&byte| byte != 0) {
                FREED_DIRTY.store(true, Ordering::SeqCst);
            }
            FREED.fetch_add(1, Ordering::SeqCst);
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    #[test]
    fn blocks_are_zero_when_freed_or_moved() {
        let allocator = WipeOnFree(Probe);
        let layout = Layout::from_size_align(32 * 1024, 8).unwrap();
        unsafe {
            let block = allocator.alloc(layout);
            assert!(!block.is_null());
            std::ptr::write_bytes(block, b'S', layout.size());

            // Growing moves the data; the old block must be wiped.
            let grown = allocator.realloc(block, layout, 64 * 1024);
            assert!(!grown.is_null());
            assert_eq!(*grown.add(layout.size() - 1), b'S');
            assert_eq!(FREED.load(Ordering::SeqCst), 1);

            let grown_layout = Layout::from_size_align(64 * 1024, 8).unwrap();
            std::ptr::write_bytes(grown, b'S', grown_layout.size());
            allocator.dealloc(grown, grown_layout);
        }
        assert_eq!(FREED.load(Ordering::SeqCst), 2);

        // A large block takes the page-discard path; it must be just as clean.
        let large = Layout::from_size_align(3 * DISCARD_THRESHOLD + 123, 8).unwrap();
        unsafe {
            let block = allocator.alloc(large);
            assert!(!block.is_null());
            std::ptr::write_bytes(block, b'S', large.size());
            allocator.dealloc(block, large);
        }
        assert_eq!(FREED.load(Ordering::SeqCst), 3);
        assert!(
            !FREED_DIRTY.load(Ordering::SeqCst),
            "a block was freed with plaintext"
        );
    }
}
