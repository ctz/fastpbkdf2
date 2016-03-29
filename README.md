# fastpbkdf2
This is a fast PBKDF2-HMAC-{SHA1,SHA256,SHA512} implementation in C.

It uses OpenSSL's hash functions, but out-performs OpenSSL's own PBKDF2
thanks to [various optimisations in the inner loop](https://jbp.io/2015/08/11/pbkdf2-performance-matters/#strategies).

[![Build Status](https://travis-ci.org/ctz/fastpbkdf2.svg?branch=master)](https://travis-ci.org/ctz/fastpbkdf2)

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

These values are wall time, output from the `bench` tool.

### AMD64
Hash     | OpenSSL     | fastpbkdf2   | (comparison)
---------|-------------|--------------|--------------
SHA1     | 11.84s      | 3.07s        | x3.86
SHA256   | 16.54s      | 7.45s        | x2.22
SHA512   | 21.90s      | 9.33s        | x2.34

2<sup>22</sup> iterations, 1.86GHz Intel Atom N2800, amd64.

### ARM
Hash     | OpenSSL     | fastpbkdf2   | (comparison)
---------|-------------|--------------|--------------
SHA1     | 30.4s       | 4.43s        | x6.86
SHA256   | 36.52s      | 7.04s        | x5.19
SHA512   | 77.44s      | 28.1s        | x2.76

2<sup>20</sup> iterations, Raspberry Pi - 700MHz ARM11.

## Requirements
* OpenSSL's libcrypto.
* C compiler supporting C99.

## Building and testing
Run 'make test' to build and run tests.

The program `bench` provides a very basic performance comparison between OpenSSL and fastpbkdf2.

The implementation has one header and one translation unit.  This
is intended for easy integration into your project.

### Optional parallelisation of outer loop
PBKDF2 is misdesigned and you should avoid asking for more than your hash function's output length.
In other words, nout should be <= 20 for `fastpbkdf2_hmac_sha1`, <= 32 for `fastpbkdf2_hmac_sha256`
and <= 64 for `fastpbkdf2_hmac_sha512`.

If you can't avoid this (for compatibility reasons, say) compile everything with `-fopenmp`
and `-DWITH_OPENMP` to have this computation done in parallel.  Note that this has non-zero
overhead.

The program `multibench` provides a basic performance comparison for using this option.

## Windows
[Details on building for Windows](WINDOWS.md).

## License
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).

## Language bindings
* [python-fastpbkdf2](https://github.com/Ayrx/python-fastpbkdf2) by [Ayrx](https://github.com/Ayrx).
* [go-fastpbkdf2](https://github.com/ctz/go-fastpbkdf2) by me.
* [rust-fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2) by me.
* [node-fastpbkdf2](https://github.com/S-YOU/node-fastpbkdf2.git) by [S-YOU](https://github.com/S-YOU).
* [ruby-fastpbkdf2](https://github.com/S-YOU/ruby-fastpbkdf2.git) by [S-YOU](https://github.com/S-YOU).

## Author
Joseph Birr-Pixton <jpixton@gmail.com>
