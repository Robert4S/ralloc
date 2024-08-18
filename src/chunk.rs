pub use std::fmt::Write;

use std::{arch::asm, ptr};

use crate::ralloc::PAGE_SIZE;

#[macro_export]
macro_rules! print_line {
    () => {
        $crate::chunk::WriteFd::<1>.write_str("\n")
    };
    ($($arg:tt)*) => {{
        let _ = write!($crate::chunk::WriteFd::<1>, $($arg)*);
        let _ = print_line!();
    }};
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub size: usize,
    pub next: *mut Chunk,
    pub mmap_location: Option<(*mut u8, *mut u8)>,
}

impl Chunk {
    pub fn new(size: usize, next: *mut Chunk) -> Self {
        if (next as usize) > 0x20000000000000 {
            print_line!("ahh {:?}", next);
        }
        Self {
            size,
            next,
            mmap_location: None,
        }
    }
}

pub struct ChunkIter {
    prev: *mut Chunk,
    curr: *mut Chunk,
}

#[allow(unused)]
pub unsafe fn write(fd: i32, ptr: *const u8, len: usize) {
    asm!(
        "syscall",
        in("rax") 1,
        in("rdi") fd,
        in("rsi") ptr,
        in("rdx") len,
        out("rcx") _,
        out("r11") _,
        lateout("rax") _,
    );
}

pub struct WriteFd<const N: i32>;

impl<const N: i32> Write for WriteFd<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        unsafe {
            write(N, s.as_ptr() as *const _, s.len());
        }
        Ok(())
    }
}

impl Iterator for ChunkIter {
    type Item = (*mut Chunk, *mut Chunk);

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.curr.is_null() {
                None
            } else {
                let res = (self.prev, self.curr);
                // This part is fucked up and shouldnt be like this, but a random pointer somewhere
                // gets corrupted and this suppresses the segfault. it means the heap slowly
                // shrinks though
                if (self.prev as usize / PAGE_SIZE) != (self.curr as usize / PAGE_SIZE) {
                    //let _ = WriteFd::<1>.write_str("never here\n");
                    //return None;
                }
                //print_line!("next: {:?}", self.curr.read().next);
                self.prev = self.curr;
                self.curr = self.curr.read().next;
                if (self.curr as usize & 0xfff_usize) == (0x988) {
                    let curdata = self.curr.read();
                    if !curdata.next.is_null() {
                        self.curr = curdata.next.read().next;
                        self.prev = curdata.next;
                    } else {
                        return None;
                    }
                    //print_line!("at iter");
                    //print_line!("and its next is: {:?}", self.curr.read().next);
                }
                Some(res)
            }
        }
    }
}

pub struct ChunkToIter(*mut Chunk);

impl ChunkToIter {
    pub fn new(ptr: *mut Chunk) -> Self {
        Self(ptr)
    }
}

impl IntoIterator for ChunkToIter {
    type Item = (*mut Chunk, *mut Chunk);
    type IntoIter = ChunkIter;

    fn into_iter(self) -> Self::IntoIter {
        ChunkIter {
            prev: ptr::null_mut(),
            curr: self.0,
        }
    }
}
