#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/evp.h>
#include "fastpbkdf2.h"

#define PASSWORD (const void *) "password", 8
#define SALT (const void *) "saltsalt", 8

#include "benchutil.h"

static void sha1(uint32_t repeat, uint32_t iterations, size_t n)
{
  uint8_t out[64];

  assert(sizeof(out) >= n);

  proctime cpu_end, cpu_start;
  double wall_end, wall_start;
  
  cpu_start = cpu_now();
  wall_start = wall_now();

  for (uint32_t i = 0; i < repeat; i++)
    PKCS5_PBKDF2_HMAC_SHA1(PASSWORD, SALT,
                           iterations,
                           (int) n, out);
  wall_end = wall_now();
  cpu_end = cpu_now();

  printf("openssl,sha1,%u,%u,%zu,%g,%g\n",
         iterations,
         repeat,
         n,
         proctime2secs(cpu_start, cpu_end),
         wall_end - wall_start);

  cpu_start = cpu_now();
  wall_start = wall_now();

  for (uint32_t i = 0; i < repeat; i++)
    fastpbkdf2_hmac_sha1(PASSWORD, SALT,
                         iterations,
                         out, n);
  wall_end = wall_now();
  cpu_end = cpu_now();

  printf("fastpbkdf2,sha1,%u,%u,%zu,%g,%g\n",
         iterations,
         repeat,
         n,
         proctime2secs(cpu_start, cpu_end),
         wall_end - wall_start);
}

int main(void)
{
  sha1(1, 1 << 22, 16);
  sha1(1, 1 << 22, 32);
  sha1(1, 1 << 22, 48);
  sha1(1, 1 << 22, 64);

  return 0;
}

