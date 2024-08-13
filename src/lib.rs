mod ralloc;
pub use ralloc::*;

#[global_allocator]
static GLOBAL: Allocator = Allocator::new();

#[cfg(test)]
mod tests {
    use std::thread;

    #[test]
    fn large_number_of_allocations() {
        let mut v = Vec::new();
        for _ in 0..1_000_000 {
            v.push(Box::new(10));
        }
        assert_eq!(*v[0], 10);
    }

    #[test]
    fn large_allocation() {
        let v = vec![0u8; 1_000_000];
        assert_eq!(v.len(), 1_000_000);
    }

    #[test]
    fn concurrent_allocations() {
        let mut handles = Vec::new();
        for _ in 0..10 {
            let handle = thread::spawn(|| {
                let mut v = Vec::new();
                for _ in 0..100_000 {
                    v.push(Box::new(10));
                }
                assert_eq!(*v[0], 10);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn concurrent_large_allocations() {
        let mut handles = Vec::new();
        for _ in 0..10 {
            let handle = thread::spawn(|| {
                let v = vec![0u8; 1_000_000];
                assert_eq!(v.len(), 1_000_000);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
