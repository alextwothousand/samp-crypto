use samp_sdk::types::Cell;
use samp_sdk::amx::{AmxResult, AMX};

use scrypt::{ScryptParams, scrypt_simple, scrypt_check};
use bcrypt::{hash, verify};

use argon2::{Config, ThreadMode, Variant, Version, hash_encoded, verify_encoded};
use rand::Rng;

impl super::samp_crypto {
	pub fn scrypt_hash(&mut self, _:&AMX, password: String, dest: &mut Cell, size: usize, n: u32, r: u8, p: u32 ) -> AmxResult<Cell> {
		if password.chars().count() < 1 {
			return Ok(-1);
		}

		if n < 1 || r < 1 || p < 1 {
			return Ok(-1);
		}
	
		let params = ScryptParams::new(r, p, n).unwrap();
		match scrypt_simple(&password, &params) {
			Ok(result) => {
				let encoded = samp_sdk::cp1251::encode(&result)?;
				set_string!(encoded, dest, size);
			}
			Err(_) => {
				return Ok(0);
			}
		}
		
		return Ok(1);
	}

	pub fn scrypt_verify(&mut self, _:&AMX, password: String, hashed_value: String) -> AmxResult<Cell> {
		match scrypt_check(&password, &hashed_value) {
			Ok(()) => {
				return Ok(1);
			}
			Err(_) => {
				return Ok(0);
			}
		}
	}

	pub fn bcrypt_hash(&mut self, _:&AMX, password: String, dest: &mut Cell, size: usize, cost: u32) -> AmxResult<Cell> {
		if cost < 1 || cost > 30 { 
			return Ok(-1); 
		}

		let hashed = hash(&password, cost).unwrap();

		match verify(password, &hashed).unwrap() {
			true => {
				let encoded = samp_sdk::cp1251::encode(&hashed)?;
				set_string!(encoded, dest, size);
				return Ok(1);
			}
			false => return Ok(0)
		}
	}

	pub fn bcrypt_verify(&mut self, _:&AMX, password: String, hash: String) -> AmxResult<Cell> {
		match verify(password, &hash).unwrap() {
			true => return Ok(1),
			false => return Ok(0)
		}
	}

	pub fn argon2_hash(&mut self, _:&AMX, password: String, salt: String, dest: &mut Cell, size: usize, memcost: u32, timecost: u32, lanes: u32, hashlength: u32) -> AmxResult<Cell> {
		if password.chars().count() < 1 {
			return Ok(-1);
		}

		if salt.chars().count() < 8 {
			return Ok(-1);
		}

		if lanes < 1 {
			return Ok(-1);
		}

		let config = Config {
			variant: Variant::Argon2i,
			version: Version::Version13,
			mem_cost: memcost, //65536
			time_cost: timecost, // 10
			lanes: lanes, // 4
			thread_mode: ThreadMode::Parallel,
			secret: &[],
			ad: &[],
			hash_length: hashlength // 32
		};

		let mut hash = hash_encoded(password.as_bytes(), salt.as_bytes(), &config).unwrap();
		let mut matches = verify_encoded(&hash, password.as_bytes()).unwrap();
		let mut attempts = 0;

		while !matches {
			hash = hash_encoded(password.as_bytes(), salt.as_bytes(), &config).unwrap();
			matches = verify_encoded(&hash, password.as_bytes()).unwrap();
			
			if attempts == 3 {
				log!(" >> samp_crypto: A fatal error has occured: Password unable to hash (Argon2).");
				return Ok(-2);
			}
			else {
				attempts += 1;
			}
		}

		let encoded = samp_sdk::cp1251::encode(&hash)?;
    		set_string!(encoded, dest, size);
	
		return Ok(1);
	}

	pub fn argon2_verify(&mut self, _:&AMX, password: String, salt: String, hashed_value: String, memcost: u32, timecost: u32, lanes: u32, hashlength: u32) -> AmxResult<Cell> {
		if password.chars().count() < 1 {
			return Ok(-1);
		}

		if salt.chars().count() < 8 {
			return Ok(-1);
		}

		if lanes < 1 {
			return Ok(-1);
		}

		let config = Config {
			variant: Variant::Argon2i,
			version: Version::Version13,
			mem_cost: memcost, // 65536
			time_cost: timecost, // 10
			lanes: lanes, // 4
			thread_mode: ThreadMode::Parallel,
			secret: &[],
			ad: &[],
			hash_length: hashlength // 32
		};

		let mut hash = hash_encoded(password.as_bytes(), salt.as_bytes(), &config).unwrap();
		let mut matches = verify_encoded(&hash, password.as_bytes()).unwrap();
		let mut attempts = 0;

		while !matches {
			hash = hash_encoded(password.as_bytes(), salt.as_bytes(), &config).unwrap();
			matches = verify_encoded(&hash, password.as_bytes()).unwrap();
			
			if attempts == 3 {
				log!(" >> samp_crypto: A fatal error has occured: Password unable to hash (Argon2).");
				return Ok(-2);
			}
			else {
				attempts += 1;
			}
		}

		match hash == hashed_value {
			true => return Ok(1),
			false => return Ok(0)
		}
	}

	pub fn random_int(&mut self, _:&AMX, min: i32, max: i32) -> AmxResult<Cell> {
		if min >= max {
			log!(
				">> samp-crypto: Fatal error - Min max values in incorrect order.\n\
				Solution: Replace 'random_int({}, {});' with 'random_int({}, {});'",
				min, max, max, min
			);
			return Ok(-1000000);
		}
		else {
			let random_number = rand::thread_rng().gen_range(min, max + 1);
			return Ok(random_number);
		}
	}
}
