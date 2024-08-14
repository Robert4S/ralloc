use std::ptr;

use crate::ralloc::PAGE_SIZE;

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

pub struct ChunkIter {
    prev: *mut Chunk,
    curr: *mut Chunk,
}

impl ChunkIter {
    fn mychunknext(&mut self) -> Option<(*mut Chunk, *mut Chunk)> {
        unsafe {
            if self.curr.is_null() {
                None
            } else {
                let res = (self.prev, self.curr);
                if (self.prev as usize / PAGE_SIZE) != (self.curr as usize / PAGE_SIZE) {
                    // new_free crosses page boundary, cannot allocate
                    return None;
                }
                self.prev = self.curr;
                self.curr = self.curr.read().next;
                Some(res)
            }
        }
    }
}

impl Iterator for ChunkIter {
    type Item = (*mut Chunk, *mut Chunk);

    fn next(&mut self) -> Option<Self::Item> {
        self.mychunknext()
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
