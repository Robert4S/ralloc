use std::{alloc::GlobalAlloc, arch::asm, mem, ptr};

use parking_lot::Mutex;

pub struct RAllocatorInternal {
    inner: Mutex<AllocatorInner>,
}

unsafe impl Send for RAllocatorInternal {}
unsafe impl Sync for RAllocatorInternal {}

impl Default for RAllocatorInternal {
    fn default() -> Self {
        Self::new()
    }
}

impl RAllocatorInternal {
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
                    *inner = AllocatorInner::new(4096);
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

unsafe impl GlobalAlloc for RAllocatorInternal {
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

impl Iterator for Chunk {
    type Item = *mut Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next.is_null() {
            None
        } else {
            Some(self.next)
        }
    }
}

pub struct AllocatorInner {
    free: *mut Chunk,
}

impl Drop for AllocatorInner {
    fn drop(&mut self) {}
}

const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;
const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PAGE_SIZE: usize = 4096;
const MAP_FAILED: usize = usize::max_value();

#[inline]
unsafe fn mmap_chunk(size: usize) -> *mut u8 {
    let addr = std::ptr::null_mut::<*mut u8>();
    let len = size;
    let prot = PROT_READ | PROT_WRITE;
    let flags = MAP_ANONYMOUS | MAP_PRIVATE;
    let fd = -1;
    let offset = 0;
    let mapped: *mut u8;

    asm!(
        "syscall",
        in("rax") 9, // MMAP syscall code
        in("rdi") addr,
        in("rsi") len,
        in("rdx") prot,
        in("r10") flags,
        in("r8") fd,
        in("r9") offset,
        out("rcx") _,
        out("r11") _,
        lateout("rax") mapped,
    );

    mapped
}

unsafe fn alloc_chunk_ptr(size: usize, align: usize) -> *mut u8 {
    let c = mmap_chunk(size) as *mut Chunk;

    if c == MAP_FAILED as *mut Chunk {
        ptr::null_mut()
    } else {
        let mut tmp = c.add(1) as usize;
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

struct AllocResult {
    new_free: *mut Chunk,
    new_size: usize,
    produced: *mut Chunk,
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

    unsafe fn segment_free(
        &self,
        curr: &*mut Chunk,
        size: usize,
        align: usize,
    ) -> Result<Option<AllocResult>, ()> {
        if curr.read().size >= (size + mem::size_of::<Chunk>()) {
            let new_curr = (((curr.add(1) as usize) + align - 1) & !(align - 1)) as *mut Chunk;

            let new_free = (new_curr as *mut u8).add(size + mem::size_of::<Chunk>()) as *mut Chunk;

            if (new_free as usize / PAGE_SIZE) != (*curr as usize / PAGE_SIZE) {
                return Err(());
            }

            let new_size = curr.read().size - size - mem::size_of::<Chunk>();

            Ok(Some(AllocResult {
                new_free,
                new_size,
                produced: new_curr,
            }))
        } else {
            Ok(None)
        }
    }

    /// Allocate some memory
    /// # Safety
    /// No
    pub unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let align = align.max(mem::align_of::<Chunk>());
        let size = (size + mem::align_of::<Chunk>() - 1) & !(mem::align_of::<Chunk>() - 1);

        if size >= PAGE_SIZE {
            return alloc_chunk_ptr(size, align);
        }

        let mut curr = self.free;
        let mut prev: *mut Chunk = ptr::null_mut();

        while !curr.is_null() {
            match self.segment_free(&curr, size, align) {
                Ok(None) => {
                    prev = curr;
                    curr = curr.as_ref().unwrap_unchecked().next;
                }
                Err(_) => {
                    break;
                }
                Ok(Some(AllocResult {
                    new_free,
                    new_size,
                    produced,
                })) => {
                    if !prev.is_null() {
                        prev.as_mut().unwrap_unchecked().next = new_free;
                    } else {
                        self.free = new_free;
                    }
                    new_free.write(Chunk {
                        size: new_size,
                        next: curr.read().next,
                    });
                    produced.sub(1).write(Chunk {
                        size,
                        next: ptr::null_mut(),
                    });

                    return produced as *mut u8;
                }
            }
        }

        alloc_chunk_ptr(size, align)
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

        self.free.as_mut().unwrap_unchecked().next = chunk_ptr;
    }
}
