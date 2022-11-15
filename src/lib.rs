use std::{ops::{Add, BitXor}, cmp::max, convert::{TryFrom, TryInto}, fmt::Debug, marker::PhantomData};
use num::{Integer, PrimInt, Zero};
use num_traits::{WrappingAdd, WrappingSub};
use num_integer::div_ceil;
use zeroize::Zeroize;

pub mod math;
pub mod key;
pub mod rc5word;

use crate::rc5word::*;
use crate::key::RC5Key;

type NumberOfRounds = u32;

/**
Length of the blocks RC5 uses when encrypting/decrypting.
For a given word size `w`, RC5 encrypts/decrypts blocks of 2
`* w` bits at a time.
 */
pub const BLOCK_LENGTH : usize = 2;

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
	// Errors that occur during creating on an RC5 instance
	InvalidNumberOfRounds,
	InvalidKeyLength,

	// Errors that occur during setup
	InvalidLVectorLen,
	InvalidSVectorLen,

	// Errors that may occur during encryption/decryption
	ImproperlyPaddedPlaintext,
	ImproperlyPaddedCyphertext
}

/// Structure that represents an RC5 configuration to be used to encrypt/decrypt data
/// with a certain private key.
///
/// The key is not part of the struct, it is meant to be passed as a parameter to the
/// relevant methods - this means that the symbol table S is recomputed every invocation.
#[derive(Debug)]
pub struct RC5<W> {
	word_size : WordSize,
	word_type : PhantomData<W>,
	rounds : NumberOfRounds,
	key_size : KeyLength
}

impl<W> RC5<W> {
	/// Create a valid RC5 instance. Required: number of rounds this instance will execute
	/// the encryption/decryption routine, and length of the key to be used in the process.
	///
	/// This method used rudimentary type-level programming to restrict the word types W
	/// allowed to create an instance of the `RC5` struct.
	///
	/// This means that after creating an instance with a given word type, it can only be
	/// used with that word type and no other. Examples follow.
	/// 
	/// The following should fail to compile:
	///
	/// ```compile_fail
	/// use rc5_test::key::RC5Key;
	/// use rc5_test::RC5;
	///
	/// let rc5_instance : RC5<u32> = RC5::create_rc5(12, 16).unwrap();
	/// let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
	/// let s = rc5_instance.setup_rc5(key).unwrap();
	///
	/// let pt : Vec<u8>  = vec![0xEA, 0x02, 0x47, 0x14];
	/// let ct = rc5_instance.encode(&pt, &s).unwrap();
	/// ```
	///
	/// This fails because the RC5 instance was created for 32-bit words, but 8-bit plaintext
	/// was passed to it.
	///
	/// In contrast, the following will work:
	///
	/// ```
	/// # use rc5_test::key::RC5Key;
	/// # use rc5_test::RC5;
	///
	/// # let rc5_instance : RC5<u32> = RC5::create_rc5(12, 16).unwrap();
	/// # let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
	/// # let s = rc5_instance.setup_rc5(key).unwrap();
	///
	/// let pt2 : Vec<u32>  = vec![0xEA, 0x02, 0x47, 0x14];
	/// let ct = rc5_instance.encode(&pt2, &s).unwrap();
	/// ```
	///
	/// The plaintext's type annotation can be left out, and it'll be inferred to match
	/// the RC5 instance's creation type:
	///
	/// ```
	/// # use rc5_test::key::RC5Key;
	/// # use rc5_test::RC5;
	///
	/// # let rc5_instance : RC5<u32> = RC5::create_rc5(12, 16).unwrap();
	/// # let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
	/// # let s = rc5_instance.setup_rc5(key).unwrap();
	///
	/// let pt3 = vec![0xEA, 0x02, 0x47, 0x14];
	/// let ct = rc5_instance.encode(&pt3, &s).unwrap();
	/// ```
	pub fn create_rc5(rounds : NumberOfRounds, key_size : KeyLength) -> Result<RC5<W>, RC5Error>
	where W : RC5Word<T = W>
	{
		if rounds > MAX_ALLOWABLE_ROUNDS {
			return Err(RC5Error::InvalidNumberOfRounds);
		} else if key_size > MAX_ALLOWABLE_KEY_LENGTH {
			return Err(RC5Error::InvalidKeyLength);
		}

		let word_size : WordSize = W::get_size_in_bits();
		let word_type : PhantomData<W> = PhantomData;
		Ok(RC5 {
			word_size,
			word_type,
			rounds,
			key_size,
		})
	}

	/// Given a particular RC5 instance and a private key, create the key table
	/// (S in the paper) to be used in encryption/decryption.
	///
	/// Note 4
	/// By default, Rust panics at runtime when arithmetic operations over/underflow,
	/// which happens by necessity in these cryptographic operations.
	///
	/// To solve this, a few alternatives exist.
	/// The one chosen here involves using the [`num_traits`](https://docs.rs/num-traits/0.2.14/num_traits/ops/index.html)
	/// package, which has traits for the operations used by RC5 - sum, product, bit shifting.
	/// There are different traits for different behaviors - saturate at the numeric bounds of
	/// the type, perform the operation while flagging overflow should it occur, silently
	/// wrap around the bounds of the type (`Wrapping`).
	///
	/// Another alternative would be [`std::num::Wrapping`](https://doc.rust-lang.org/stable/std/num/struct.Wrapping.html),
	/// which would not require an additional crate.
	/// However, because one of the initial purposes of this crate was to offer a polymorphic
	/// implementation of RC5, this would require writing many implementations of
	///
	/// ```no_run
	/// //impl<W : Add<Output = W>> Add for Wrapping<W> {...}
	/// //impl<W : Sub<Output = W>> Sub for Wrapping<W> {...}
	/// ```
	///
	/// As these are not provided by the standard lib.
	pub fn setup_rc5(&self, mut key : RC5Key) -> Result<Vec<W>, RC5Error>
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

		L[c - 1] = W::zero();
		for i in (0 ..= self.key_size as usize - 1).rev() {
			let two = W::one() + W::one();
			let eight = two * two * two;
			// There seems to be a typo in the paper: in the pseudocode <<< is used
			// no signify rotation, but in the appendix's C implementation << is used instead.
			// However, it works.
			// L[i / u] = L[i / u].wrapping_shl(8).wrapping_add(&From::from(key[i]));
			L[i / u] = W::rotl(L[i / u], eight).wrapping_add(&From::from(key[i]));
		}

		// The encryption key is no longer needed, scrub it.
		key.zeroize();

		// The L vector needs to have c as its length after it has been initialized.
		// If it does not, that is a problem, and execution must halt.
		if L.len() != c {
			return Err(RC5Error::InvalidLVectorLen);
		}

		S[0] = W::P();
		for i in 1 ..= t - 1 {
			S[i] = S[i - 1].wrapping_add(&W::Q());
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

	/// This function should return a cipher text for a given key and plaintext.
	/// It does so one RC5 block at a time. Each block is composed of `2w` bits,
	/// where `w` is the length, in bits, of the word type chosen to run RC5 with.
	///
	/// Note 2
	/// The plaintext vector is assumed to have length 2; since this function is
	/// not public and it is the responsibility of its caller - `encode` - to
	/// only pass it pairs of words and check for the size of the key table,
	/// that is not done here.
	fn encode_block(&self, plaintext : &[W; 2], key_table : &[W]) -> [W; 2]
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
		let mut A : W = plaintext[0].wrapping_add(&key_table[0]);
		let mut B : W = plaintext[1].wrapping_add(&key_table[1]);

		for i in 1 ..= self.rounds as usize
		{
			A = W::rotl(A.bitxor(B), B).wrapping_add(&key_table[2 * i]);
			B = W::rotl(B.bitxor(A), A).wrapping_add(&key_table[2 * i + 1]);
		}

		[A, B]
	}

	pub fn encode(&self, plaintext : &[W], key_table : &[W]) -> Result<Vec<W>, RC5Error>
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
		if plaintext.len().is_zero() {
			return Ok(vec![]);
		}

		// The plaintext could be padded here, but then, when decoding, it'd require a way to
		// keep track of whether the last word in the plaintext was added by this function or not.
		if plaintext.len().is_odd() {
			return Err(RC5Error::ImproperlyPaddedPlaintext);
		}

		let cyphertext = plaintext
			.chunks(BLOCK_LENGTH)
			.flat_map(|chunk| {
				self.encode_block(chunk.try_into().unwrap(), key_table)
			})
			.collect::<Vec<_>>();

		Ok(cyphertext)
	}

	/// This function should return the plaintext generated by a given key on some
	/// cyphertext.
	/// It does so one RC5 block at a time. Each block is composed of `2w` bits,
	/// where `w` is the length, in bits, of the word type chosen to run RC5 with.
	///
	/// Note 2
	/// The plaintext vector is assumed to have length 2; since this function is
	/// not public and it is the responsibility of its caller - `decode` - to
	/// only pass it pairs of words and check for the size of the key table,
	/// that is not done here.
	fn decode_block(&self, cyphertext : &[W; 2], key_table : &[W]) -> [W; 2]
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
		let mut B : W = cyphertext[1];
		let mut A : W = cyphertext[0];

		for i in (1 ..= self.rounds as usize).rev()
		{
			B = W::rotr(B.wrapping_sub(&key_table[2 * i + 1]), A).bitxor(A);
			A = W::rotr(A.wrapping_sub(&key_table[2 * i]), B).bitxor(B);
		}

		[A.wrapping_sub(&key_table[0]), B.wrapping_sub(&key_table[1])]
	}

	pub fn decode(&self, cyphertext : &[W], key_table : &[W]) -> Result<Vec<W>, RC5Error>
	// See Note 3 for the reason why these bounds differ from those in `RC5::encode`.
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
		if cyphertext.len().is_zero() {
			return Ok(vec![]);
		}
	
		// Different situation here: because it has already been encrypted, the cyphertext
		// cannot at all have odd length.
		if cyphertext.len().is_odd() {
			return Err(RC5Error::ImproperlyPaddedCyphertext);
		}

		// The plaintext's length has already been checked not to be odd, or zero.
		// It is therefore safe to call `decode_block` here. A similar reasoning applies
		// to `encode_block`, see Note 2.
		let plaintext = cyphertext
			.chunks(BLOCK_LENGTH)
			.flat_map(|chunk| {
				self.decode_block(chunk.try_into().unwrap(), key_table)
			})
			.collect::<Vec<_>>();
		
		Ok(plaintext)
	}


}

#[cfg(test)]
mod tests {
	use super::*;

	fn encode_decode_test<W>(key : RC5Key, pt : Vec<W>, res_ct : Vec<W>, rounds : u32, key_size : usize)
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
		let rc5_instance : RC5<W> = RC5::create_rc5(rounds, key_size).unwrap();
		let s = rc5_instance.setup_rc5(key).unwrap();

		let ct = rc5_instance.encode(&pt, &s).unwrap();

		let res_pt = rc5_instance.decode(&ct, &s).unwrap();

		assert!(&ct[..] == &res_ct[..]);
		assert!(&pt[..] == &res_pt[..]);
	}

	fn encode_decode_test_16_12<W>(key : RC5Key, pt : Vec<W>, res_ct : Vec<W>)
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
		let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
		let pt : Vec<u8>  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u8> = vec![0x00, 0x89, 0xA5, 0x0C, 0x08, 0x89, 0x0E, 0x9F];

		encode_decode_test_16_12(key, pt, ct)
	}
	
	#[test]
	fn encode_16() {
		let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u16> = vec![0x8B59, 0x3948, 0xAA2F, 0x8307, 0xC0F5, 0xABF4, 0x2078, 0x1D7F];
		encode_decode_test_16_12(key, pt, ct);
	}

	#[test]
	fn encode_32() {
		let key = RC5Key::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
		let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
		let ct : Vec<u32> = vec![0x92BF7F69, 0xD6A03212, 0x9D61F96E, 0x9A231988, 0x93420E37, 0x1F4C830F, 0x78194BB3, 0x78B09E02];
		encode_decode_test_16_12(key, pt, ct);
	}

	#[test]
	fn encode_64() {
		let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
		let pt : Vec<u64>  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let res_ct : Vec<u64> = vec![0xBB0497B712B4E725, 0x37992017930E3A36, 0xE36E715550078AD3, 0x1C956B32BCB63824, 0x2B3A8E4AF93600F7, 0x52D48295E9F6D4D0, 0xBB65F6F5FC1CE043, 0xC453962B6C91D01E];
		encode_decode_test_16_12(key, pt, res_ct);
	}

	#[test]
	fn encode_128() {
		let key = RC5Key::new(vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48]);
		let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
		let ct : Vec<u128> = vec![0xF5FB70072DB9D97B0148D85D973E7A6B, 0x247DDBDF9F5E89393CA6772C82B244CC, 0xEFD0F78D74A4EF684D5A86E8DB44EC80, 0xA08E96515249009F1BD13588DA68BC47, 0x896E491ED22D1CD1F98D5DDFC8C5A806, 0xAB482F1650A83132B742882D068A7DCD, 0x15A3B452E5D350098C0673191546965A, 0x9C4C21D80E8D7474C7957E150C002F07];
		encode_decode_test_16_12(key, pt, ct);
	}

}
