#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/times.h>

#include <openssl/evp.h>
#include "fastpbkdf2.h"

#define PASSWORD (const void *) "password", 8
#define SALT (const void *) "saltsalt", 8

#define WARMUP 4096
#define ITERATIONS (1 << 22)

static clock_t now(void)
{
  struct tms tms;
  times(&tms);
  return tms.tms_utime;
}

static double clock2secs(clock_t start, clock_t end)
{
  assert(end >= start);
  return (end - start) / (double) sysconf(_SC_CLK_TCK);
}

static void sha1(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[20];

  clock_t end, start = now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC_SHA1(PASSWORD, SALT,
                           iterations,
                           (int) sizeof(out), out);
  end = now();
  printf("openssl,sha1,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));

  start = now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha1(PASSWORD, SALT,
                         iterations,
                         out, sizeof out);
  end = now();
  printf("fastpbkdf2,sha1,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));
}

static void sha256(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[32];

  clock_t end, start = now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                      iterations,
                      EVP_sha256(),
                      (int) sizeof(out), out);
  end = now();
  printf("openssl,sha256,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));

  start = now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha256(PASSWORD, SALT,
                           iterations,
                           out, sizeof out);
  end = now();
  printf("fastpbkdf2,sha256,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));
}

static void sha512(uint32_t repeat, uint32_t iterations)
{
  uint8_t out[64];

  clock_t end, start = now();
  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                      iterations,
                      EVP_sha512(),
                      (int) sizeof(out), out);
  end = now();
  printf("openssl,sha512,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));

  start = now();
  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha512(PASSWORD, SALT,
                           iterations,
                           out, sizeof out);
  end = now();
  printf("fastpbkdf2,sha512,%u,%u,%g\n", iterations, repeat, clock2secs(start, end));
}

#define RUNTESTS(fn) \
  fn(1 << 8, 1 << 14); \
  fn(1 << 6, 1 << 16); \
  fn(1 << 4, 1 << 18); \
  fn(1 << 2, 1 << 20); \
  fn(1 << 0, 1 << 22)

int main(void)
{
  RUNTESTS(sha1);
  RUNTESTS(sha256);
  RUNTESTS(sha512);

  return 0;
}

