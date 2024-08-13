use std::{alloc::GlobalAlloc, mem, ptr};

use libc::{mmap, sysconf, MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, _SC_PAGESIZE};
use parking_lot::Mutex;

/// Custom global allocator implemented using a free list.
/// # Usage
/// ```rust
/// #[global_allocator]
/// static GLOBAL: RAllocator = RAllocator::new();
/// // This will make you program use the RAllocator allocator for all heap allocations
/// ```
pub struct RAllocator {
    inner: Mutex<AllocatorInner>,
}

unsafe impl Send for RAllocator {}
unsafe impl Sync for RAllocator {}

impl Default for RAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl RAllocator {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(AllocatorInner {
                free: ptr::null_mut(),
            }),
        }
    }

    pub unsafe fn r_alloc(&self, size: usize, align: usize) -> *mut u8 {
        loop {
            if let Some(mut inner) = self.inner.try_lock() {
                if inner.free.is_null() {
                    *inner = AllocatorInner::new(12228);
                }
                return inner.alloc(size, align);
            }
        }
    }

    pub unsafe fn r_dealloc(&self, ptr: *mut u8) {
        loop {
            if let Some(mut inner) = self.inner.try_lock() {
                inner.free(ptr);
                return;
            }
        }
    }
}

unsafe impl GlobalAlloc for RAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.r_alloc(layout.pad_to_align().size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: std::alloc::Layout) {
        self.r_dealloc(ptr)
    }
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub size: usize,
    pub next: *mut Chunk,
}

pub struct AllocatorInner {
    free: *mut Chunk,
}

impl Drop for AllocatorInner {
    fn drop(&mut self) {}
}

#[inline]
unsafe fn mmap_chunk(size: usize) -> *mut u8 {
    let addr = std::ptr::null_mut::<libc::c_void>();
    let len = size;
    let prot = PROT_READ | PROT_WRITE;
    let flags = MAP_ANON | MAP_PRIVATE;
    let fd = -1;
    let offset = 0;

    mmap(addr, len, prot, flags, fd, offset) as *mut u8
}

impl AllocatorInner {
    pub unsafe fn new(size: usize) -> Self {
        let chunk = mmap_chunk(size) as *mut Chunk;

        chunk.write(Chunk {
            size,
            next: ptr::null_mut(),
        });
        Self { free: chunk }
    }

    /// Allocate some memory
    /// # Safety
    /// No
    pub unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let align = align.max(mem::align_of::<Chunk>());
        let mut size = size;
        while (size % mem::align_of::<Chunk>()) != 0 {
            size += 1;
        }
        let mut curr = self.free;
        let mut prev: *mut Chunk = ptr::null_mut();
        let page_size = sysconf(_SC_PAGESIZE) as usize;

        while !curr.is_null() {
            if curr.read().size >= (size + mem::size_of::<Chunk>()) {
                let mut tmp = curr.add(1) as usize;
                while (tmp % align) != 0 {
                    tmp += 1;
                }
                let new_curr = tmp as *mut Chunk;

                let new_free =
                    (new_curr as *mut u8).add(size + mem::size_of::<Chunk>()) as *mut Chunk;

                if (new_free as usize / page_size) != (curr as usize / page_size) {
                    break;
                }

                let new_size = curr.read().size - size - mem::size_of::<Chunk>();

                if !prev.is_null() {
                    prev.as_mut().unwrap().next = new_free;
                } else {
                    self.free = new_free;
                }

                new_free.write(Chunk {
                    size: new_size,
                    next: curr.read().next,
                });

                new_curr.sub(1).write(Chunk {
                    size,
                    next: ptr::null_mut(),
                });

                return new_curr as *mut u8;
            }
            prev = curr;
            curr = curr.as_ref().unwrap().next;
        }

        let chunk = mmap_chunk(size) as *mut Chunk;

        if chunk == MAP_FAILED as *mut Chunk {
            ptr::null_mut()
        } else {
            let mut tmp = chunk.add(1) as usize;
            while (tmp % align) != 0 {
                tmp += 1;
            }
            let new_chunk = tmp as *mut Chunk;

            new_chunk.sub(1).write(Chunk {
                size,
                next: ptr::null_mut(),
            });

            new_chunk as *mut u8
        }
    }

    /// Deallocate some memory
    /// # Safety
    /// No. No desegmentation. after a few allocs i hand you over to mmap
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        let chunk_ptr = (ptr as *mut Chunk).sub(1);
        chunk_ptr.write(Chunk {
            next: self.free.read().next,
            ..chunk_ptr.read()
        });

        self.free.as_mut().unwrap().next = chunk_ptr;
    }
}
