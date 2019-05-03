// NOTE:change the name of include to samp-crypto
// remove built-in include guard
#if defined _inc_samp_crypto
	#undef _inc_samp_crypto
#endif
// custom include-guard
#if defined _samp_crypto_included
	#endinput
#endif
#define _samp_crypto_included

// general
#define CRYPTO_UNSUCCESSFUL 0
#define CRYPTO_SUCCESSFUL   1

#define CRYPTO_ERROR_PARAMS -1
#define CRYPTO_ERROR_FATAL  -2

// scrypt related
#define SCRYPT_HASH_LEN 100

#define SCRYPT_COST 15
#define SCRYPT_RAM 8
#define SCRYPT_CPU 1

// bcrypt related
#define BCRYPT_COST_ERROR -1
#define BCRYPT_COST 12

// argon2 related
#define ARGON2_HASH_LEN 100 // can be changed at your own will.

#define ARGON2_MEMCOST 3000 // was 65535, lowered to reduce hashing time
#define ARGON2_TIMECOST 2 // was 10, same reason as memcost
#define ARGON2_LANES 4 // this also equates to the amount of threads

/*  scrypt_hash()
	Parameters:
	* password - The password to be hashed. (Must be 1 char at minimum)
	* dest - Where the hashed password is stored.
	* size - The size of dest.
	* N - The CPU & RAM cost (you should only ever need to modify this value at most)
	* R - RAM cost
	* P - CPU cost

	Returns:
	* 1 - Hash successful.
	* 0 - Salt or password are insufficient.
	* -1 - One of the parameters (Nrp) do not meet the minimum criteria of 1. You should leave them as default.
*/
native scrypt_hash(const password[], dest[], size = sizeof dest, n = SCRYPT_COST, r = SCRYPT_RAM, p = SCRYPT_CPU);

/*  scrypt_verify()
	Parameters:
	* password - The password entered by the player.
	* hashedpass - The password retrieved from database.

	Returns:
	* 0 - Passwords do not match.
	* 1 - Passwords match.
*/
native scrypt_verify(const password[], const hashed_value[]);

/*  bcrypt_hash()
	Parameters:
	* password - The password to be hashed (Must be 1 char at minimum)
	* dest - Destination hash.
	* size - The size of the destination string.
	* cost - The password workfactor. Defaults to 12.

	Returns:
	* 1 - hash successful.
	* 0 - hash unsuccessful.
	* -1 - Cost was not specified, or is below 1, or is above 30.
*/
native bcrypt_hash(const password[], dest[], size = sizeof dest, cost = BCRYPT_COST);

/*  bcrypt_verify()
	Parameters:
	* Password - The password to be checked against the hash
	* Hash - The hash to be checked against the password.

	Returns:
	* 1 - Password matches.
	* 0 - Password does not match.
*/
native bcrypt_verify(const password[], const hash[]);

/*  argon2_hash()
	Parameters:
	* password - The password to be hashed. (Must be 1 char at minimum)
	* salt - A little sprinkle of salt to be added to the password. (Must be 8 chars at minimum)
	* dest - Where the hashed password is stored.
	* size - The size of dest.
	* memcost - Memory allocated towards hashing.
	* timecost - Time allocated towards hashing.
	* lanes - Related to threading.
	* hashlength - Max length of your password hash.

	Returns:
	* 1 - Hash successful.
	* -1 - Salt or password are insufficient.
	* -1 - Lanes are below 1. They should remain the specified default.
	* -2 - Fatal error occured.
*/
native argon2_hash(const password[], const salt[], dest[], size = sizeof dest, memcost = ARGON2_MEMCOST, timecost = ARGON2_TIMECOST, lanes = ARGON2_LANES, hashlength = ARGON2_HASH_LEN);

/*  argon2_compare()
	Parameters:
	* password - The password entered by the player.
	* salt - The player's salt.
	* hashedpass - The password retrieved from database.

	Returns:
	* 0 - Passwords do not match.
	* 1 - Passwords match.
	* -1 - Password is below 1, salt is below 8 or lanes are below 1.
	* -2 - A fatal error occured.
*/
native argon2_verify(const password[], const salt[], const hashed_value[], memcost = ARGON2_MEMCOST, timecost = ARGON2_TIMECOST, lanes = ARGON2_LANES, hashlength = ARGON2_HASH_LEN);

/*  random_int()
    Parameters:
	* min
	* max

	Returns:
	- The randomly generated number.
	- 1000000 - The min value is above the max value. You will get a console error with a solution.

	Notes:
	If you specify 1 as your min and 10 as your max, you will get a number between 1-10.
*/
native random_int(min, max);
