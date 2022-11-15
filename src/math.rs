/// This module serves to expose a simple API to calculate the magic constants P and Q
/// for various word sizes, using the `rug` crate for arbitrary-precision floating
/// point calculations.
///
/// The code in `main.rs` is enough to print the constants onto STDOUT, so the code 
/// below serves as
/// * a reminder on how to use modules
/// * more experiments on closures, both returning them from and passing them to functions
/// * practice to learn how to define and initialize static variables using `lazy_static`
use rug::{float::Round, Float, Integer};
use std::collections::HashMap;
use lazy_static::lazy_static;

lazy_static!{
	/// This is a `Hashmap` that maps word sizes, in bits, to the corresponding
	/// value of the `Q` constant for that word type e.g. `QS.get(128)` is
	/// the value of `Q` for `u128`.
	/// `PS` does the same for the `P` constant.
	pub static ref QS : HashMap<u32, Integer> = {
		let mut h = HashMap::new();
		for i in (3 ..= 7).map(|n| {2u32.pow(n)}) {
			h.insert(i, q_w_prec_200(i));	
		}
		h
	};
	pub static ref PS : HashMap<u32, Integer> = {
		let mut h = HashMap::new();
		for i in (3 ..= 7).map(|n| {2u32.pow(n)}) {
			h.insert(i, p_w_prec_200(i));	
		}
		h
	};
}

fn round_to_nearest_odd(fl : Float) -> impl Fn() -> Integer {
	let round_to_nearest_odd = move || {
		let low = fl.to_integer_round(Round::Down).map(|opt| { opt.0 }).unwrap_or(Integer::new());
		let high = fl.to_integer_round(Round::Up).map(|opt| { opt.0 }).unwrap_or(Integer::new());
		let nearest = fl.to_integer_round(Round::Nearest).map(|opt| { opt.0 }).unwrap_or(Integer::new());

		if nearest.is_odd() {
			nearest
		// If the nearest number is not odd, it must be even, so the furthest must be odd.
		// At this point it is unknown which is the furthest, whether the floor `low` or the
		// ceiling `high`.
		} else if high == nearest {
			low
		} else {
			high
		}
	};
	round_to_nearest_odd
}

fn p_w_wrapper<F>(f : F, w : u32, prec : u32) -> Integer
where F : Fn(u32, u32) -> Integer
{
	f(w, prec)
}

fn p_w(w : u32, prec : u32) -> Integer
{
	let p_w = |w : u32, prec : u32| {
		let f = Float::with_val(200, 1);
		let e = f.exp();

		// This clone() is necessary because of closure semantics.
		// Were this not cloned, then p_w would not be callable more than
		// once, as rug::Float does not implement Copy.
		let f1 = e - 2;

		let pow = Float::i_pow_u(2, w);
		let f2 = Float::with_val(prec, pow);

		round_to_nearest_odd(f1 * f2)()
	};

	p_w_wrapper(p_w, w, prec)
}

fn p_w_prec_200(w : u32) -> Integer
{
	p_w(w, 200)
}

fn q_w (w : u32, prec : u32) -> Integer
{
	let sqrt5 = Float::with_val(prec, 5.0).sqrt();
	let phi = (1 + sqrt5) / 2;
	let f1 = phi - 1;

	let pow = Float::i_pow_u(2, w);
	let f2 = Float::with_val(prec, pow);

	round_to_nearest_odd(f1 * f2)()
}

fn q_w_prec_200(w : u32) -> Integer
{
	q_w(w, 200)
}