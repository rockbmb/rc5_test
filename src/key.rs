use std::ops::Index;

use zeroize::{Zeroize, ZeroizeOnDrop};

// Can't seem to derive these traits like this, it's either
// because I don't know enough about derive macros and cargo features,
// or because of a subtle bug - very unlikely.
// #![cfg(feature = "zeroize_derive")]
//#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RC5Key(Vec<u8>);

impl RC5Key {
    pub fn new(bytes : Vec<u8>) -> Self {
        RC5Key(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Index<usize> for RC5Key {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl Zeroize for RC5Key {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl ZeroizeOnDrop for RC5Key {}