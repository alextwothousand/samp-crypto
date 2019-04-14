#[macro_use]
extern crate samp_sdk;
extern crate scrypt;

extern crate bcrypt;
extern crate argon2;

extern crate base64;
extern crate byteorder;

extern crate rand;

mod plugin;
mod natives;

use plugin::samp_crypto;

new_plugin!(samp_crypto);


