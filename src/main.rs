use std::env;
use rc5_test::RC5;

fn main() {
	env::set_var("RUST_BACKTRACE", "1");

	let rc5_instance : RC5;

	rc5_instance = RC5::create_rc5::<u32>(12, 16).unwrap();

	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
	let s = rc5_instance.setup_rc5::<u32>(key).unwrap();
	println!("{:02X?}", s);
	println!("{0}", s.len());
}