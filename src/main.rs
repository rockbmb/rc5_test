use std::{env, collections::HashMap};
use rc5_test::RC5;

use rug::{float::{Round, Constant}, Float, Integer};

fn main() {
	env::set_var("RUST_BACKTRACE", "1");
	println!("---");

	let pi = Float::with_val(53, Constant::Pi);

	let f = Float::with_val(200, 1);
	let e = f.exp();

	// This is necessary to calculate the magic constants P and Q: round
	// a Float to the nearest odd Integer.
	let round_to_nearest_odd = |fl : Float| {
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

	let p_w = |w : u32, prec : u32| {
		// This clone() is necessary because of closure semantics.
		// Were this not cloned, then p_w would not be callable more than
		// once, as rug::Float does not implement Copy.
		let f1 = e.clone() - 2;

		let pow = Float::i_pow_u(2, w);
		let f2 = Float::with_val(prec, pow);

		round_to_nearest_odd(f1 * f2)
	};
	let p_w_prec_200 = |w| {p_w(w, 200)};

	let q_w = |w : u32, prec : u32| {
		let sqrt5 = Float::with_val(prec, 5.0).sqrt();
		let phi = (1 + sqrt5) / 2;
		let f1 = phi - 1;

		let pow = Float::i_pow_u(2, w);
		let f2 = Float::with_val(prec, pow);

		round_to_nearest_odd(f1 * f2)
	};
	let q_w_prec_200 = |w| {q_w(w, 200)};

	let mut ps = HashMap::new();
	let mut qs = HashMap::new();
	for i in (3 ..= 7).map(|n| {2u32.pow(n)}) {
		ps.insert(i, p_w_prec_200(i));

		qs.insert(i, q_w_prec_200(i));
	}

	for i in (3 ..= 7).map(|n| {2u32.pow(n)}) {
		println!(
			"p_{:03}: {:032} ---- q_{:03}: {:032}",
			i,
			ps.get(&i).unwrap().to_string_radix(16),
			i,
			qs.get(&i).unwrap().to_string_radix(16)
	);
	}
}