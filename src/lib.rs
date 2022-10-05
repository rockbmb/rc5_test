use std::{ops::{Rem, Add, BitXor}, cmp::max, convert::{TryFrom, TryInto}, fmt::Debug};
use num::{Integer, PrimInt, Zero};
use num_traits::{WrappingAdd, WrappingSub};
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

impl RC5Word for u8 {
	type T = u8;

	fn get_size_in_bits() -> WordSize {
		u8::BITS
	}

	fn P() -> u8 {
		0xb7
	}

	fn Q() -> u8 {
		0x9f
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

impl RC5Word for u128 {
	type T = u128;

	fn get_size_in_bits() -> WordSize {
		u128::BITS
	}

	fn P() -> u128 {
		0xb7e151628aed2a6abf7158809cf4f3c7
	}

	fn Q() -> u128 {
		0x9e3779b97f4a7c15f39cc0605cedc835
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
		})
	}

	pub fn setup_rc5<W>(&self, key: Vec<u8>) -> Result<Vec<W>, RC5Error>
	where W : RC5Word<T = W> +
			  WrappingAdd +
			  Add<Output = W> +
			  PrimInt +
			  From<u8> +
			  TryFrom<u32> +
			  TryInto<u32>,
			  <W as TryFrom<u32>>::Error: Debug,
			  <W as TryInto<u32>>::Error: Debug
	{
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
		let mut A : W = plaintext[0].wrapping_add(&key_table[0]);
		let mut B : W = plaintext[1].wrapping_add(&key_table[1]);

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

		plaintext[1] = B.wrapping_sub(&key_table[1]);
		plaintext[0] = A.wrapping_sub(&key_table[0]);

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

#[cfg(test)]
mod tests {
	use super::*;

	fn encode_decode_test<W>(key : Vec<u8>, pt : Vec<W>, res_ct : Vec<W>, rounds : u32, key_size : usize)
	where W : RC5Word<T = W> +
		  WrappingAdd +
		  WrappingSub +
		  PrimInt +
		  BitXor +
		  From<u8> +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		let rc5_instance = RC5::create_rc5::<W>(rounds, key_size).unwrap();
		let s = rc5_instance.setup_rc5::<W>(key).unwrap();

		let ct = rc5_instance.encode(&pt, &s).unwrap();

		let res_pt = rc5_instance.decode(&ct, &s).unwrap();

		assert!(&ct[..] == &res_ct[..]);
		assert!(&pt[..] == &res_pt[..]);
	}

	fn encode_decode_test_16_12<W>(key : Vec<u8>, pt : Vec<W>, res_ct : Vec<W>)
	where W : RC5Word<T = W> +
		  WrappingAdd +
		  WrappingSub +
		  PrimInt +
		  BitXor +
		  From<u8> +
		  TryFrom<u32> +
		  TryInto<u32> +
		  Copy,
		  <W as TryFrom<u32>>::Error: Debug,
		  <W as TryInto<u32>>::Error: Debug
	{
		encode_decode_test(key, pt, res_ct, 12, 16)
	}

	#[test]
	fn encode_8() {
		let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u8> = vec![0x00, 0x89, 0xA5, 0x0C, 0x08, 0x89, 0x0E, 0x9F];
		encode_decode_test_16_12(key, pt, ct)
	}
	
	#[test]
	fn encode_16() {
		let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u16> = vec![0x8B59, 0x3948, 0xAA2F, 0x8307, 0xC0F5, 0xABF4, 0x2078, 0x1D7F];
		encode_decode_test_16_12(key, pt, ct);
	}

    #[test]
    fn encode_32() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
		let ct : Vec<u32> = vec![0x92BF7F69, 0xD6A03212, 0x9D61F96E, 0x9A231988, 0x93420E37, 0x1F4C830F, 0x78194BB3, 0x78B09E02];
		encode_decode_test_16_12(key, pt, ct);
	}

	#[test]
    fn encode_64() {
		let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u64> = vec![0xBB0497B712B4E725, 0x37992017930E3A36, 0xE36E715550078AD3, 0x1C956B32BCB63824, 0x2B3A8E4AF93600F7, 0x52D48295E9F6D4D0, 0xBB65F6F5FC1CE043, 0xC453962B6C91D01E];
		encode_decode_test_16_12(key, pt, ct);
	}

	#[test]
    fn encode_128() {
		let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u128> = vec![0xF5FB70072DB9D97B0148D85D973E7A6B, 0x247DDBDF9F5E89393CA6772C82B244CC, 0xEFD0F78D74A4EF684D5A86E8DB44EC80, 0xA08E96515249009F1BD13588DA68BC47, 0x896E491ED22D1CD1F98D5DDFC8C5A806, 0xAB482F1650A83132B742882D068A7DCD, 0x15A3B452E5D350098C0673191546965A, 0x9C4C21D80E8D7474C7957E150C002F07];
		encode_decode_test_16_12(key, pt, ct);
	}

}
