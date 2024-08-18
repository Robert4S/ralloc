use crate::{chunk::*, print_line};
use std::{alloc::GlobalAlloc, arch::asm, mem, ptr};

use parking_lot::Mutex;

const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
pub const PAGE_SIZE: usize = 4096;
const MAP_FAILED: usize = usize::max_value();
const MMAP_PROT: i32 = PROT_READ | PROT_WRITE;
const MMAP_FLAGS: i32 = MAP_ANONYMOUS | MAP_PRIVATE;
const MMAP_FD: i32 = -1;
const MMAP_OFFSET: i64 = 0;

pub struct RAllocatorInternal {
    inner: Mutex<AllocatorInner>,
}

unsafe impl Send for RAllocatorInternal {}
unsafe impl Sync for RAllocatorInternal {}

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
                    *inner = AllocatorInner::new(10000);
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
        if layout.size() == 0 {
            return 0x10000000 as *mut u8;
        }
        self.r_alloc(layout.pad_to_align().size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        if layout.size() == 0 {
            return;
        }
        self.r_dealloc(ptr)
    }
}

#[derive(Clone, Copy)]
pub struct AllocatorInner {
    free: *mut Chunk,
}

unsafe fn mmap_mem(size: usize) -> *mut u8 {
    let mapped: *mut u8;

    asm!(
        "syscall",
        in("rax") 9, // MMAP syscall code
        in("rdi") 0, // let kernel give me whatever address
        in("rsi") size,
        in("rdx") MMAP_PROT,
        in("r10") MMAP_FLAGS,
        in("r8") MMAP_FD,
        in("r9") MMAP_OFFSET,
        out("rcx") _,
        out("r11") _,
        lateout("rax") mapped,
    );

    mapped
}

pub struct FreeErr;

unsafe fn munmap(ptr: *mut u8, size: usize) -> Result<(), FreeErr> {
    let res: i32;

    asm!(
        "syscall",
        in("rax") 11, // munmap syscall code
        in("rdi") ptr,
        in("rsi") size,
        out("rcx") _,
        out("r11") _,
        lateout("rax") res,
    );

    if res == 0 {
        Ok(())
    } else {
        Err(FreeErr)
    }
}

unsafe fn alloc_chunk_ptr(size: usize, align: usize, sep: bool) -> *mut u8 {
    let chunk = mmap_mem(size) as *mut Chunk;

    if chunk == MAP_FAILED as *mut Chunk {
        ptr::null_mut()
    } else {
        let mut tmp = chunk.add(1) as usize;
        while (tmp % align) != 0 {
            tmp += 1;
        }
        let new_chunk = tmp as *mut Chunk;
        if sep {
            new_chunk.sub(1).write(Chunk {
                size,
                next: ptr::null_mut(),
                mmap_location: Some((chunk as *mut u8, (chunk as *mut u8).add(size))),
            })
        } else {
            new_chunk.sub(1).write(Chunk::new(size, ptr::null_mut()));
        }

        new_chunk as *mut u8
    }
}

struct AllocResult {
    new_free: *mut Chunk,
    new_size: usize,
    ptr_to_give: *mut Chunk,
}

impl AllocatorInner {
    pub unsafe fn new(size: usize) -> Self {
        let chunk = mmap_mem(size) as *mut Chunk;

        chunk.write(Chunk::new(size, ptr::null_mut()));

        Self { free: chunk }
    }

    unsafe fn segment_free(
        &self,
        curr: &*mut Chunk,
        size: usize,
        align: usize,
    ) -> Result<Option<AllocResult>, ()> {
        if curr.read().size >= (size + mem::size_of::<Chunk>()) {
            // align will be max(align_of::<Chunk>(), align_of::<T>()), so this will round the
            // pointer to be aligned properly so that T can be stored at it, and a Chunk can be
            // stored right before it
            let ptr_to_give = (((curr.add(1) as usize) + align - 1) & !(align - 1)) as *mut Chunk;

            let new_free =
                (ptr_to_give as *mut u8).add(size + mem::size_of::<Chunk>()) as *mut Chunk;

            if (new_free as usize / PAGE_SIZE) != (*curr as usize / PAGE_SIZE) {
                // new_free crosses page boundary, cannot allocate
                return Err(());
            }

            if (new_free as usize) > 0x20000000000000 {
                print_line!("ahh {:?}", new_free);
            }

            let new_size = curr.read().size - size - mem::size_of::<Chunk>();

            Ok(Some(AllocResult {
                new_free,
                new_size,
                ptr_to_give,
            }))
        } else {
            Ok(None)
        }
    }

    fn force(i: &mut impl Iterator) {
        while let Some(_) = i.next() {}
    }

    /// Allocate some memory
    /// # Safety
    /// No
    pub unsafe fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let align = align.max(mem::align_of::<Chunk>());

        // round size up to be divisible by align of chunk, so that the calculated offset will
        // always be fine to store a chunk
        let size = (size + mem::align_of::<Chunk>() - 1) & !(mem::align_of::<Chunk>() - 1);

        if size >= PAGE_SIZE {
            return alloc_chunk_ptr(size, align, true);
        }

        let ptr = self
            .into_iter()
            .map(|(prev, curr)| (prev, curr, self.segment_free(&curr, size, align)))
            .filter_map(|(prev, curr, res)| match res {
                Ok(Some(res)) => Some((prev, curr, res)),
                _ => None,
            })
            .next();

        match ptr {
            None => alloc_chunk_ptr(size, align, true),
            Some((prev, curr, allocres)) => {
                if !prev.is_null() {
                    prev.as_mut().unwrap_unchecked().next = allocres.new_free;
                } else {
                    self.free = allocres.new_free;
                }

                allocres
                    .new_free
                    .write(Chunk::new(allocres.new_size, curr.read().next));

                allocres
                    .ptr_to_give
                    .sub(1)
                    .write(Chunk::new(size, ptr::null_mut()));

                allocres.ptr_to_give as *mut u8
            }
        }
    }

    /// Deallocate some memory
    /// # Safety
    /// No. No desegmentation. after a few allocs i hand you over to mmap
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        let chunk_ptr = (ptr as *mut Chunk).sub(1);
        let ptrdata = chunk_ptr.read();

        if !ptrdata.next.is_null() {
            panic!();
        }

        chunk_ptr.write(Chunk {
            next: self.free,
            ..ptrdata
        });

        self.free = chunk_ptr;
    }
}

impl IntoIterator for AllocatorInner {
    type Item = (*mut Chunk, *mut Chunk);
    type IntoIter = ChunkIter;

    fn into_iter(self) -> Self::IntoIter {
        ChunkToIter::new(self.free).into_iter()
    }
}
