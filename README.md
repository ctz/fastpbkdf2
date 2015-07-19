# fastpbkdf2
This is a fast PBKDF2-HMAC-{SHA1,SHA256,SHA512} implementation in C.

It uses OpenSSL's hash functions, but out-performs OpenSSL's own PBKDF2
thanks to various optimisations in the inner loop.

[![Build Status](https://travis-ci.org/ctz/fastpbkdf2.svg)](https://travis-ci.org/ctz/fastpbkdf2)

## Interface

```c
void fastpbkdf2_hmac_sha1(const uint8_t *pw, size_t npw,
                          const uint8_t *salt, size_t nsalt,
                          uint32_t iterations,
                          uint8_t *out, size_t nout);

void fastpbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);

void fastpbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout);
```

Please see the header file for details and constraints.

## Performance

Hash     | OpenSSL     | fastpbkdf2   | (faster by %)
---------|-------------|--------------|--------------
SHA1     | 11.84s      | 3.18s        | 372%
SHA256   | 16.54s      | 7.62s        | 217%
SHA512   | 21.90s      | 9.83s        | 222%

(non-scientific, walltime output from `bench`, 2^<sup>22</sup> iterations, 1.86GHz Intel Atom N2800)

## Requirements
* OpenSSL's libcrypto.
* C compiler supporting C99.

## Building and testing
Run 'make test' to build and run tests.

The program `bench` provides a very basic performance comparison between OpenSSL and fastpbkdf2.

The implementation has one header and one translation unit.  This
is intended for easy integration into your project.

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
