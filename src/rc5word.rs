use std::{convert::{TryFrom, TryInto}, fmt::Debug, ops::Rem};
use num::PrimInt;

pub type WordSize = u32;

/// The `RC5Word` trait serves to restrict which primitive word types can serve
/// as plaintext/cyphertext for RC5.
///
/// Only data from types that implement this trait can be encrypted using this module.
/// This means that using e.g. signed word types like `i32` that do not implement
/// this trait will fail at compile-time.
///
/// Note 3
/// The reason this trait relies on an associated type instead of generics is that
/// generics would permit the same unsigned word type - e.g. `u32` - to offer more
/// than one implementation, which in this context would not make sense.
///
/// This is unfortunate because with generics, one could add bounds to `T` in `RC5Word<T>`
/// that, by describing what we'd need from `T`, e.g. `WrappingAdd + WrappingShl + ...`, would
/// restrict implementations of this trait only to types that would make sense to use in RC5
/// encryption e.g. `u16, u64`, and prevent the need to add complex bounds to every method;
/// see `RC5::{encode, decode}`.
///
/// However, for now, it is not possible to add bounds to associated types - see
/// [this](https://github.com/rust-lang/rust/issues/44265) - so they have to be
/// present in methods in traits, and methods in `impl`s for `struct`s.
/// This means each method can have only the bounds it requires, leading to different
/// bounds on methods that all act on the same type.
///
/// Ultimately, since all of them require `RCWord`, that will not matter - this
/// is what this trait is for.
pub trait RC5Word
{
	type T;

	fn get_size_in_bits() -> WordSize;

	fn P() -> Self::T;

	fn Q() -> Self::T;

	/// Note 1
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

	/// See Note 1
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

	// Showcasing use of the P static variable, a hashmap populated lazily at run-time,
	// to get the P magic constant for the 8-bit word type.
	fn P() -> u8 {
		crate::math::PS
			.get(&u8::get_size_in_bits())
			.map(|i| {i.to_u8_wrapping()})
			.unwrap_or(0xb7)
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

	fn get_size_in_bits() -> WordSize {
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