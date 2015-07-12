#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include "fastpbkdf2.h"

#define PASSWORD (const void *) "password", 8
#define SALT (const void *) "saltsalt", 8
#define ITERATIONS (1 << 22)

static double now(void)
{
  struct timeval tv = { 0, 0 };
  gettimeofday(&tv, NULL);

  double r = tv.tv_sec;
  r += (double) tv.tv_usec * 1e-6;
  return r;
}

static void sha1(void)
{
  uint8_t out[20];

  double start = now();
  PKCS5_PBKDF2_HMAC_SHA1(PASSWORD, SALT,
                         ITERATIONS,
                         (int) sizeof(out), out);
  printf("openssl sha1 = %gs\n", now() - start);

  start = now();
  fastpbkdf2_hmac_sha1(PASSWORD, SALT,
                       ITERATIONS,
                       out, sizeof out);
  printf("fastpbkdf2 sha1 = %gs\n", now() - start);
}

static void sha256(void)
{
  uint8_t out[32];

  double start = now();
  PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                    ITERATIONS,
                    EVP_sha256(),
                    (int) sizeof(out), out);
  printf("openssl sha256 = %gs\n", now() - start);

  start = now();
  fastpbkdf2_hmac_sha256(PASSWORD, SALT,
                         ITERATIONS,
                         out, sizeof out);
  printf("fastpbkdf2 sha256 = %gs\n", now() - start);
}

static void sha512(void)
{
  uint8_t out[64];

  double start = now();
  PKCS5_PBKDF2_HMAC(PASSWORD, SALT,
                    ITERATIONS,
                    EVP_sha512(),
                    (int) sizeof(out), out);
  printf("openssl sha512 = %gs\n", now() - start);

  start = now();
  fastpbkdf2_hmac_sha512(PASSWORD, SALT,
                         ITERATIONS,
                         out, sizeof out);
  printf("fastpbkdf2 sha512 = %gs\n", now() - start);
}

int main(void)
{
  sha1();
  sha256();
  sha512();

  return 0;
}

