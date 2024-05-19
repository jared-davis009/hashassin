- All functionality supported including errors and tracing

- Can be called as described in the doc
    - gen-password requires:
        --num-to-gen
    -  gen-hashes requires:
        --in-path

- Used trace, debug, error, and info levels of tracing

- Errors show when min_char > max_char for passwords and when unsupported hash algorithm is called

- Cool thing to for you guys to note: Our use of generics allowed us to implement and add many simple hashing algorithms without many additional lines of code

Supported the following algorithms (algorithms must be called as shown):
- Argon2
- Md5
- Sha2_256
- Sha2_512
- Sha1
- Sha3_256
- Sha3_224
- Shabal256
- Shabal224
- Shabal192
- Shabal512
- Shabal384
- Ascon2
- Sm3
- Ripdemd320
- Ripdemd128
- Ripemd256
- Fsb160
- Fsb224
- Fsb256
- Fsb512
- Fsb384
- Jh224
- Jh256
- Jh384
- Jh512
- Tiger
- Tiger2
- Belthash
- Streebog256
- Streebog512
- Md4
- Groestl224
- Groestl256
- Groestl384
- Groestl512
- Gost94