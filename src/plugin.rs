use samp_sdk::consts::*;
use samp_sdk::types::Cell;
use samp_sdk::amx::AMX;

define_native!(
	scrypt_hash,
	password: String,
	dest: ref Cell,
	size: usize,
	n: u32,
	r: u8,
	p: u32
);

define_native!(
	scrypt_verify,
	password: String,
	hashed_value: String
);

define_native!(
	bcrypt_hash,
	password: String,
	dest: ref Cell,
	size: usize,
	cost: u32
);

define_native!(
	bcrypt_verify,
	password: String,
	hash: String
);

define_native!(
	argon2_hash,
	password: String,
	salt: String,
	dest: ref Cell,
	size: usize,
	memcost: u32,
	timecost: u32,
	lanes: u32,
	hashlength: u32
);

define_native!(
	argon2_verify,
	password: String,
	salt: String,
	hashed_value: String,
	memcost: u32,
	timecost: u32,
	lanes: u32,
	hashlength: u32
);

define_native!(
	random_int,
	min: i32,
	max: i32
);

pub struct samp_crypto;

impl samp_crypto {
	pub fn load(&self) -> bool {
		log!(" >> samp-crypto: 1.0 loaded.");
		return true;
	}

	pub fn unload(&self) {
		log!(" >> samp-crypto: 1.0 unloaded.");
	}

	pub fn amx_load(&mut self, amx: &mut AMX) -> Cell {
		let natives = natives!{
			"scrypt_hash" => scrypt_hash,
			"scrypt_verify" => scrypt_verify,

			"bcrypt_hash" => bcrypt_hash,
			"bcrypt_verify" => bcrypt_verify,

			"argon2_hash" => argon2_hash,
			"argon2_verify" => argon2_verify,

			"random_int" => random_int
		};

		match amx.register(&natives) {
			Ok(_) => log!(" >> samp-crypto: Natives have successful loaded."),
			Err(err) => log!(" >> samp-crypto: An error has occured: {:?}", err),
		}

		AMX_ERR_NONE
	}

	pub fn amx_unload(&self, _: &mut AMX) -> Cell {
		AMX_ERR_NONE
	}

}

impl Default for samp_crypto {
	fn default() -> Self {
		samp_crypto {
		}
	}
}