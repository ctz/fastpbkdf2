#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/evp.h>
#include "fastpbkdf2.h"

#define PASSWORD (const void *) "password", 8
#define SALT (const void *) "saltsalt", 8

#define WARMUP 4096
#define ITERATIONS (1 << 22)

#include "benchutil.h"

static void sha1(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[20];

  proctime end, start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC_SHA1(PASSWORD, SALT,
                           iterations,
                           (int) sizeof(out), out);
  end = cpu_now();
  printf("openssl,sha1,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));

  start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha1(PASSWORD, SALT,
                         iterations,
                         out, sizeof out);
  end = cpu_now();
  printf("fastpbkdf2,sha1,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));
}

static void sha256(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[32];

  proctime end, start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                      iterations,
                      EVP_sha256(),
                      (int) sizeof(out), out);
  end = cpu_now();
  printf("openssl,sha256,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));

  start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha256(PASSWORD, SALT,
                           iterations,
                           out, sizeof out);
  end = cpu_now();
  printf("fastpbkdf2,sha256,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));
}

static void sha512(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[64];

  proctime end, start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                      iterations,
                      EVP_sha512(),
                      (int) sizeof(out), out);
  end = cpu_now();
  printf("openssl,sha512,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));

  start = cpu_now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha512(PASSWORD, SALT,
                           iterations,
                           out, sizeof out);
  end = cpu_now();
  printf("fastpbkdf2,sha512,%u,%u,%g\n", iterations, repeat, proctime2secs(start, end));
}

int main(int argc, char **argv)
{
  unsigned total_iterations_log2 = 22;

  if (argc == 2)
  {
    total_iterations_log2 = atoi(argv[1]);
    assert(total_iterations_log2 > 12);
  }

  for (unsigned iterations = total_iterations_log2,
                reps = 1;
       iterations >= 12;
       iterations -= 2, reps <<= 2)
  {
    sha1(reps, 1 << iterations);
    sha256(reps, 1 << iterations);
    sha512(reps, 1 << iterations);
  }

  return 0;
  
  (void) wall_now;
}

