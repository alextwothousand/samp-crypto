// Big thanks to Dakyskye for this!

#include <a_samp>
#include <samp-crypto>

#define RUN_TESTS
#include <YSI_Core\y_testing>

#define R_MIN 339
#define R_MAX 114921

new const password[] = "asdj1hj2hh12hasdkasdk";
new const salt[] = "5hh5hasdi1";

new 
	hashed[256],
	err
; 

Test:Scrypt_Test() {
	err = scrypt_hash(password, hashed);
	ASSERT(err == 1);
	err = scrypt_verify(password, hashed);
	ASSERT(err == 1);
}

Test:Bcrypt_Test() {
	err = bcrypt_hash(password, 15, hashed);
	ASSERT(err == 1);
	err = bcrypt_verify(password, hashed);
	ASSERT(err == 1);
}

Test:Argon2_Test() {
	err = argon2_hash(password, salt, hashed);
	ASSERT(err == 1);
	err = argon2_verify(password, salt, hashed);
	ASSERT(err == 1);
}

Test:RandomInt_Test() {
	err = random_int(R_MIN, R_MAX);
	ASSERT(R_MIN <= err <= R_MAX);
}