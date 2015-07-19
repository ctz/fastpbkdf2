# fastpbkdf2
This is a fast PBKDF2-HMAC-{SHA1,SHA256,SHA512} implementation in C.

It uses OpenSSL's hash functions, but out-performs OpenSSL's own PBKDF2
thanks to various optimisations in the inner loop.

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
SHA1     | 3.92s       | 1.58s        | 249%
SHA256   | 6.56s       | 4.13s        | 159%
SHA512   | 8.48s       | 5.35s        | 159%

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
