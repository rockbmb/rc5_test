use std::{ops::{Rem, Add, BitXor}, cmp::max, convert::{TryFrom, TryInto}, fmt::Debug};
use num::{Integer, PrimInt, Zero};
use num_traits::{WrappingAdd, WrappingShl, WrappingSub};
use num_integer::div_ceil;

type WordSize = u32;

type NumberOfRounds = u32;

/**
 * Maximum allowable number of rounds, by default the paper advised it to be 255.
 */
pub const MAX_ALLOWABLE_ROUNDS : NumberOfRounds = 255;

type KeyLength = usize;

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
	InvalidSVectorLen,

	ImproperlyPaddedPlaintext,
	ImproperlyPaddedCyphertext
}

pub trait RC5Word
{
	type T;

	fn get_size_in_bits() -> WordSize;

	fn P() -> Self::T;

	fn Q() -> Self::T;

	/// [Note 1]
	/// The reason TryInto can be unwrapped so carelessly is the following:
	/// - The unsigned word types to be used all have bit lengths that
	/// obviously fit into a u32 - u128 is the highest that Rust does natively offer
	///
	/// - The second argument of `PrimInt::rotate_{left, right}`, the amount of bits
	/// to rotate, has to be of type `u32`.
	/// - However, given a particular type e.g. `u128`, a rotation by `n : u32` bits
	/// is the same as a rotation by `n % 128` bits
	///
	/// This means that when converting the number of bits to rotate by into `u32`,
	/// the only important result is modulo the word size, which will always fit
	/// into `u32`, regardless of whether there exists a `From` or `TryFrom` instance
	/// into that type.
	fn rotl(x : Self::T, y_ : Self::T) -> Self::T
	where Self::T : PrimInt +
		  TryFrom<u32> +
		  TryInto<u32>,
		  <<Self as RC5Word>::T as TryFrom<u32>>::Error: Debug,
		  <<Self as RC5Word>::T as TryInto<u32>>::Error: Debug
	{
		let w = Self::T::try_from(Self::get_size_in_bits()).unwrap();

		let y = y_.rem(w);
		x.rotate_left(y.try_into().unwrap())
	}

	/// See [Note 1]
	fn rotr(x : Self::T, y_ : Self::T) -> Self::T
	where Self::T : PrimInt +
		  TryFrom<u32> +
		  TryInto<u32>,
		  <<Self as RC5Word>::T as TryFrom<u32>>::Error: Debug,
		  <<Self as RC5Word>::T as TryInto<u32>>::Error: Debug
	{
	let w = Self::T::try_from(Self::get_size_in_bits()).unwrap();

	let y = y_.rem(w);
	x.rotate_right(y.try_into().unwrap())
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

		if rounds > MAX_ALLOWABLE_ROUNDS {
			return Err(RC5Error::InvalidNumberOfRounds);
		} else if key_size > MAX_ALLOWABLE_KEY_LENGTH {
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
	where W : RC5Word<T = W> +
			  Integer +
			  WrappingAdd +
			  Add<Output = W> +
			  WrappingShl +
			  PrimInt +
			  From<u8> +
			  TryFrom<u32> +
			  TryInto<u32>,
			  <W as TryFrom<u32>>::Error: Debug,
			  <W as TryInto<u32>>::Error: Debug {
		if self.key_size != key.len() {
			return Err(RC5Error::InvalidKeyLength);
		}

		let c : usize =  max(1, div_ceil(8 * self.key_size, self.word_size as usize)) as usize;
		let u : usize = self.word_size as usize / 8;
		let mut L  : Vec<W> = vec![W::zero(); c];
		let t : usize = 2 * (self.rounds as usize + 1);
		let mut S : Vec<W> = vec![W::zero(); t];

		L[c-1] = W::zero();
		for i in (0 ..= self.key_size as usize - 1).rev() {
			let two = W::one() + W::one();
			let eight = two * two * two;
			// There seems to be a typo in the paper: in the pseudocode <<< is used
			// no signify rotation, but in the implementation << is used instead.
			// However, the following line also works.
			//L[i / u] = L[i / u].wrapping_shl(8).wrapping_add(&From::from(key[i]));
			L[i / u] = W::rotl(L[i / u], eight).wrapping_add(&From::from(key[i]));
		}

		// The L vector needs to have c as its length when it is initialized.
		// If it does not, that is a problem, and execution must halt.
		if L.len() != c {
			return Err(RC5Error::InvalidLVectorLen);
		}

		S[0] = W::P();
		for i in 1 ..= t - 1 {
			S[i] = S[i-1].wrapping_add(&W::Q());
		}
		// Same for the S vector here.
		if S.len() != t {
			return Err(RC5Error::InvalidSVectorLen);
		}

		let mut A : W = W::zero();
		let mut B : W = W::zero();

		let mut i : usize = 0;
		let mut j : usize = 0;

		let three = W::one() + W::one() + W::one();
		for _ in 1 ..= 3 * max(t, c) {
			S[i] = W::rotl(S[i].wrapping_add(&A.wrapping_add(&B)), three );
			A = S[i];

			L[j] = W::rotl(L[j].wrapping_add(&A.wrapping_add(&B)), A.wrapping_add(&B));
			B = L[j];

			i = (i + 1) % t;
			j = (j + 1) % c;
		}

		println!("b: {0}; c: {1}; u: {2}; t: {3}", self.key_size, c, u, t);

		Ok(S)
	}

	/// This function should return a cipher text for a given key and plaintext
	fn encode_block<W>(&self, plaintext : &[W], key_table : &[W]) -> Vec<W>
	where W : RC5Word<T = W> +
		  WrappingAdd +
		  PrimInt +
		  BitXor +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		let mut cyphertext = vec![W::zero(); 2];
		let mut A : W = plaintext[0] + key_table[0];
		let mut B : W = plaintext[1] + key_table[1];

		for i in 1 ..= self.rounds as usize
		{
			A = W::rotl(A.bitxor(B), B).wrapping_add(&key_table[2 * i]);
			B = W::rotl(B.bitxor(A), A).wrapping_add(&key_table[2 * i + 1]);
		}

		cyphertext[0] = A;
		cyphertext[1] = B;

		cyphertext
	}

	pub fn encode<W>(&self, plaintext : &[W], key_table : &[W]) -> Result<Vec<W>, RC5Error>
	where W : RC5Word<T = W> +
		  WrappingAdd +
		  PrimInt +
		  BitXor +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		// The plaintext could be padded here, but then, when decoding, it'd require a way to
		// keep track of whether the last word in the plaintext was added by this function or not.
		if plaintext.len().is_odd() {
			return Err(RC5Error::ImproperlyPaddedPlaintext);
		}
		let mut cyphertext = vec![W::zero(); plaintext.len()];
		if cyphertext.len().is_zero() {
			return Ok(cyphertext);
		}

		// This loop is overengineered for sure, but I was curious to see how slice copying worked;
		// [using this](https://doc.rust-lang.org/std/primitive.slice.html#method.copy_from_slice).
		for i in (0 .. plaintext.len()).step_by(2)
		{
			cyphertext[i ..= i + 1].copy_from_slice(&self.encode_block(&plaintext[i ..= i + 1], key_table));
		}

		Ok(cyphertext)
	}

 	/// This function should return a plaintext for a given key and ciphertext
	fn decode_block<W>(&self, cyphertext : &[W], key_table : &[W]) -> Vec<W>
	where W : RC5Word<T = W> +
		  WrappingSub +
		  PrimInt +
		  BitXor +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		let mut plaintext = vec![W::zero(); 2];
		let mut B : W = cyphertext[1];
		let mut A : W = cyphertext[0];

		for i in (1 ..= self.rounds as usize).rev()
		{
			B = W::rotr(B.wrapping_sub(&key_table[2 * i + 1]), A).bitxor(A);
			A = W::rotr(A.wrapping_sub(&key_table[2 * i]), B).bitxor(B);
		}

		plaintext[1] = B - key_table[1];
		plaintext[0] = A - key_table[0];

		plaintext
	}

	pub fn decode<W>(&self, cyphertext : &[W], key_table : &[W]) -> Result<Vec<W>, RC5Error>
	where W : RC5Word<T = W> +
		  WrappingSub +
		  PrimInt +
		  BitXor +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		// Different situation here: because it has already been encrypted, the cyphertext
		// cannot at all have odd length.
		if cyphertext.len().is_odd() {
			return Err(RC5Error::ImproperlyPaddedCyphertext);
		}
		let mut plaintext  = vec![W::zero(); cyphertext.len()];
		if plaintext.len().is_zero() {
			return Ok(plaintext);
		}

		for i in (0 .. plaintext.len()).step_by(2) {
			plaintext[i ..= i + 1].copy_from_slice(&self.decode_block(&cyphertext[i ..= i + 1], key_table));
		}

		Ok(plaintext)
	}


}

 fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
	let mut ciphertext = Vec::new();
	ciphertext
}

fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
	let mut plaintext = Vec::new();
	plaintext
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn encode_a() {
		let rc5_instance = RC5::create_rc5::<u32>(12, 16).unwrap();

		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let s = rc5_instance.setup_rc5::<u32>(key).unwrap();

		let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

		let ct = rc5_instance.encode(&pt, &s).unwrap();
		
		let res : Vec<u32> = vec![0x92BF7F69, 0xD6A03212, 0x9D61F96E, 0x9A231988, 0x93420E37, 0x1F4C830F, 0x78194BB3, 0x78B09E02];

		println!("pt: {:02X?}", pt);
		println!("ct: {:02X?}", ct);
		println!("res: {:02X?}", res);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key : Vec<u8> = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct : Vec<u8>  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

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
