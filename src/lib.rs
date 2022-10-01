use std::{ops::{BitOr, BitXor, BitAnd, Shl, Shr}, cmp::max};
use num::{One, Integer};
use num_traits::ops::wrapping;
use num_integer::div_ceil;

type WordSize = u32;

type NumberOfRounds = u32;

/**
 * Maximum allowable number of rounds, by default the paper advised it to be 255.
 */
pub const MAX_ALLOWABLE_ROUNDS : NumberOfRounds = 255;

type KeyLength = u32;

/**
 * Maximum allowable size of key in bytes, by default the paper advised it to be 255.
 */
pub const MAX_ALLOWABLE_KEY_LENGTH : KeyLength = 255;

type KeyTableSize = u32;

type BlockLength = u32;

#[derive(Debug)]
pub enum RC5Error {
	InvalidNumberOfRounds,
	InvalidKeyLength,
	InvalidLVectorLen,
	InvalidSVectorLen
}

pub trait RC5Word
{
	type T;

	fn get_size_in_bits() -> WordSize;

	fn P() -> Self::T;

	fn Q() -> Self::T;

	fn rotl(x : Self::T, y : Self::T) -> Self::T
	where Self::T : Integer +
		  BitOr<Output = Self::T> +
		  BitXor<Output = Self::T> +
		  BitAnd<Output = Self::T> +
		  Shl<Output = Self::T> +
		  Shr<Output = Self::T> +
		  From<u32> +
		  Copy
	{
		let w : Self::T = Self::T::from(Self::get_size_in_bits());
		let left = x.shl(y.bitand(w - Self::T::one()));
		let right = x.shr(w - y.bitand(w - Self::T::one()));
		left.bitor(right)
	}

	fn rotr(x : Self::T, y : Self::T) -> Self::T
	where Self::T : Integer +
		  BitOr<Output = Self::T> +
		  BitXor<Output = Self::T> +
		  BitAnd<Output = Self::T> +
		  Shl<Output = Self::T> +
		  Shr<Output = Self::T> +
		  From<u32> +
		  Copy
	{
		let w : Self::T = Self::T::from(Self::get_size_in_bits());
		let left = x.shr(y.bitand(w - Self::T::one()));
		let right = x.shl(w - y.bitand(w - Self::T::one()));
		left.bitor(right)
	}
}

impl RC5Word for u32 {
	type T = u32;

	fn get_size_in_bits() -> WordSize{
		u32::BITS
	}

	fn P() -> u32 {
		0xb7e15163
	}

	fn Q() -> u32 {
		0x9e3779b9
	}
}

impl RC5Word for u16 {
	type T = u16;

	fn get_size_in_bits() -> WordSize {
		u16::BITS
	}

	fn P() -> u16 {
		0xb7e1
	}

	fn Q() -> u16 {
		0x9e37
	}
}

impl RC5Word for u64 {
	type T = u64;

	fn get_size_in_bits() -> WordSize {
		u64::BITS
	}

	fn P() -> u64 {
		0xb7e151628aed2a6b
	}

	fn Q() -> u64 {
		0x9e3779b97f4a7c15
	}
}

/// Structure that represents an RC5 configuration to be used to encrypt/decrypt data
/// with a certain private key.
///
/// They key is not part of the struct, it is meant to be passed as a parameter to the
/// relevant methods - this means that the symbol table S is recomputed every invocation.
#[derive(Debug)]
pub struct RC5 {
	word_size : WordSize,
	rounds : NumberOfRounds,
	key_size : KeyLength,

	key_table_size : KeyTableSize,

	/// RC5 is a block cypher, so it can only encrypt blocks of fixed size at a time - this field
	/// denotes its length.
	block_length : BlockLength
}

impl RC5 {
	pub fn create_rc5<T : RC5Word>(rounds : NumberOfRounds, key_size : KeyLength) -> Result<RC5, RC5Error> {

		if rounds < 0 || rounds > MAX_ALLOWABLE_ROUNDS {
			return Err(RC5Error::InvalidNumberOfRounds);
		} else if key_size < 0 || key_size > MAX_ALLOWABLE_KEY_LENGTH {
			return Err(RC5Error::InvalidKeyLength);
		}

		let w : WordSize = T::get_size_in_bits();
		Ok(RC5 {
			word_size : w,
			rounds,
			key_size,
			key_table_size : 2 * rounds + 1,
			block_length : 2 * w
		})
	}

	pub fn setup_rc5<W>(&self, key: Vec<u8>) -> Result<Vec<W>, RC5Error>
	where W : Copy +
			  RC5Word<T = W> +
			  Integer +
			  From<u32> +
			  Shl<Output = W> +
			  BitOr<Output = W> +
			  BitAnd<Output = W> +
			  BitXor<Output = W> +
			  Shr<Output = W> {
		let c : usize =  max(1, div_ceil(8 * self.key_size, self.word_size)) as usize;
		let u : usize = self.word_size as usize / 8;
		let mut L  : Vec<W> = vec![W::from(0); c];
		let t : usize = 2 * (self.rounds as usize) + 1;
		let mut S : Vec<W> = vec![W::from(0); t];

		L[c-1] = W::from(0);
		for i in (0 .. self.key_size as usize - 1).rev() {
			L[i / u] = L[i/u] << W::from(8) + W::from(key[i].into());
		}
		if L.len() != c {
			return Err(RC5Error::InvalidLVectorLen);
		}

		S[0] = W::P();
		for i in 1 .. t-1 {
			S[i] = S[i-1] + W::Q();
		}
		if L.len() != t {
			return Err(RC5Error::InvalidSVectorLen);
		}

		let mut A : W = W::from(0);
		let mut B : W = W::from(0);

		let mut i : usize = 0;
		let mut j : usize = 0;
		let mut k : usize = 0;

		while k < 3 * max(t, c) {
			S[i] = W::rotl(S[i] + A + B, W::from(3));
			A = S[i];

			L[j] = W::rotl(L[j] + A + B, A + B);
			B = L[j];

			i = (i + 1) % t;
			j = (j + 1) % c;
			k += 1;
		}

		Ok(S)
	}

}

/*
* This function should return a cipher text for a given key and plaintext
*
*/
 fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
	let mut ciphertext = Vec::new();
	ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
	let mut plaintext = Vec::new();
	plaintext
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn encode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }
}
