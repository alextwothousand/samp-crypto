# samp-crypto
A SAMP cryptography plugin written in Rust.
This plugin was written as a means to make it really simple for anyone to transition from Whirlpool, SHA256_PassHash or any other hashing method similar to these without major script changes, like the other bcrypt plugins do.
This is my first plugin written in Rust, I tried cleaning up all my code and I will continue to do so however you may still see some legacy code. If you wish to clean it up please fork the repo, make changes and create a PR! I will happily review it.

### Encryption methods
* Argon2 (specifically Argon2i, a update including Argon2d and Argon2id will come soon)
* Scrypt
* Bcrypt

### Plans for future additions
I plan on adding encryption methods like HMAC, so on and so fourth. If you have any to suggest please open up a issue.

### How to Use
* Head to the release page and download the latest version of samp crypto (https://github.com/infin1tyy/samp-crypto/releases).
* Place the .inc into your pawno/include folder.
* Place the .dll or .so in your plugins folder (if one doesn't exist, create a new one).
* Add `samp_crypto` to your server.cfg (if on linux, add `libsamp_crypto.so` to your server.cfg instead.
* Enjoy!

### Credits
* SyS - A lot of stuff :)
* Southclaws - advice
* iAmir - Testing
* Dakyskye - Testing and the unit test.pwn.
* Gravityfalls - Testing
* MicroKyrr/Kiru - Testing
* And anyone else that I didn't mention!


