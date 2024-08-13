mod ralloc;
pub use ralloc::*;

#[global_allocator]
static GLOBAL: Allocator = Allocator::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut v = vec![];
        for _ in 0..1000 {
            v.push(10);
        }
        println!("{v:?}");
        assert_eq!(v.as_slice(), &[10; 1000])
    }
}
