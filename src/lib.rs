use std::{ops::{Mul, Add, BitOr, BitXor, BitAnd, Sub, Shl, Shr}};
use num::One;

enum SupportedRC5WordType {
	Word16,
	Word32,
	Word64
}

impl SupportedRC5WordType {
	fn get_size_in_bits(&self) -> u32 {
		match self {
			Self::Word16 => u16::BITS,
			Self::Word32 => u32::BITS,
			Self::Word64 => u64::BITS
		}
	}
}

type WordSize = u32;

type NumberOfRounds = u32;

type KeySize = u32;

type KeyTableSize = u32;

type BlockLength = u32;

trait RC5Word
{
	type T;

	fn get_size_in_bits() -> WordSize;

	fn P() -> Self::T;

	fn Q() -> Self::T;

	fn rotl(x : Self::T, y : Self::T) -> Self::T
	where Self::T : Add<Output = Self::T> +
		  Mul<Output = Self::T> +
		  BitOr<Output = Self::T> +
		  BitXor<Output = Self::T> +
		  BitAnd<Output = Self::T> +
		  Shl<Output = Self::T> +
		  Shr<Output = Self::T> +
		  Sub<Output = Self::T> +
		  From<u32> +
		  One +
		  Copy
	{
		let w : Self::T = Self::T::from(Self::get_size_in_bits());
		let left = x.shl(y.bitand(w - Self::T::one()));
		let right = x.shr(w - y.bitand(w - Self::T::one()));
		left.bitor(right)
	}

	fn rotr(x : Self::T, y : Self::T) -> Self::T
	where Self::T : Add<Output = Self::T> +
		  Mul<Output = Self::T> +
		  BitOr<Output = Self::T> +
		  BitXor<Output = Self::T> +
		  BitAnd<Output = Self::T> +
		  Shl<Output = Self::T> +
		  Shr<Output = Self::T> +
		  Sub<Output = Self::T> +
		  From<u32> +
		  One +
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

/**
 * Structure that represents an RC5 configuration to be used to encrypt/decrypt data
 * with a certain private key.
 * 
 * They key is not part of the struct, it is meant to be passed as a parameter to the
 * relevant methods - this means that the symbol table S is recomputed every invocation.
 */
struct RC5 {
	word_size : WordSize,
	rounds : NumberOfRounds,
	key_size : KeySize,

	key_table_size : KeyTableSize,

	/// RC5 is a block cypher, so it can only encrypt blocks of fixed size at a time - this field
	/// denotes its length.
	block_length : BlockLength
}

impl RC5 {
	fn create_rc5<T : RC5Word>(rounds : NumberOfRounds, key_size : KeySize) -> RC5 {
		let w : WordSize = T::get_size_in_bits();

		RC5 {
			word_size : w,
			rounds,
			key_size,
			key_table_size : 2 * rounds + 1,
			block_length : 2 * w
		}
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
