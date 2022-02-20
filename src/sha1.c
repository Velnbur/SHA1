/*
The MIT License (MIT)

Copyright (c) 2022 Kyrylo Baibula

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "sha1.h"

#define CHUNK_SIZE 64 /* in bytes */
#define INT32_SIZE 4  /* in bytes */

#define _SEG_LEN CHUNK_SIZE / INT32_SIZE
/* return 512-bit chunk from string as array
 * of 32 bit ints in 'res'. If len is less then
 * CHUNK_SIZE - unfilled elements in array will
 * be zero.
 * */
static void get_chunk(const char *mess, size_t len, uint32_t res[_SEG_LEN]) {
  int i, j;
  size_t res_len = len < CHUNK_SIZE ? len : CHUNK_SIZE;

  for (i = 0; i < _SEG_LEN - 1; ++i)
    res[i] = 0;
  res[_SEG_LEN - 1] = res_len * CHAR_BIT;

  j = 0;
  uint32_t tmp = 0;
  for (i = 0; i < res_len; ++i) {
    tmp = (tmp << CHAR_BIT) + mess[i];
    if ((i + 1) % INT32_SIZE == 0 && i != 0) {
      res[j] = tmp;
      j++;
      tmp = 0;
    }
  }

  /* add 0x80 byte to the last unfilled byte of chunck */
  if (j != _SEG_LEN - 1)
    res[j] = (tmp << CHAR_BIT) + 0x80;
  else
    res[j] = tmp;
}

/*
** Leftrotate 32-bit integer by 'bits' values.
**
** For example, if we need to rotate a byte '1010 1000'
** by one, result will be '0101 0001'. That is just
** left shift with setting overflowed bits to the end.
*/
static uint32_t leftrotate(uint32_t num, uint bits) {
  return (num << bits) + (num >> (INT32_SIZE * CHAR_BIT - bits));
}

/*
** Builds result hash from five pieces for SHA1 alg.
** SHA1 result is a 160-bit or 20-byte array that
** will be builded from five pieces (h0, h1, h2, h3, h4)
** that are used in algorithm.
*/
static void build_hash(uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3,
                       uint32_t h4, char res[HASH_SIZE]) {
  int i;
  for (i = 0; i < HASH_SIZE; ++i) {
    if (i < 4) {
      res[HASH_SIZE - i - 1] = (char)(h0 & 0xff); /* getting last byte */
      h0 >>= CHAR_BIT;
    } else if (i < 8) {
      res[HASH_SIZE - i - 1] = (char)(h1 & 0xff);
      h1 >>= CHAR_BIT;
    } else if (i < 12) {
      res[HASH_SIZE - i - 1] = (char)(h2 & 0xff);
      h2 >>= CHAR_BIT;
    } else if (i < 16) {
      res[HASH_SIZE - i - 1] = (char)(h3 & 0xff);
      h3 >>= CHAR_BIT;
    } else if (i < 20) {
      res[HASH_SIZE - i - 1] = (char)(h4 & 0xff);
      h4 >>= CHAR_BIT;
    }
  }
}

/* Special initialization values for SHA1 algoritm */
enum STD_INIT_VALS {
  H0_INIT = 0x67452301,
  H1_INIT = 0xEFCDAB89,
  H2_INIT = 0x98BADCFE,
  H3_INIT = 0x10325476,
  H4_INIT = 0xC3D2E1F0,
  K_LEVEL1 = 0x5A827999,
  K_LEVEL2 = 0x6ED9EBA1,
  K_LEVEL3 = 0x8F1BBCDC,
  K_LEVEL4 = 0xCA62C1D6,
};

/*
** Get F function depending on round 't'
*/
static uint32_t func(uint32_t x, uint32_t y, uint32_t z, uint32_t t) {
  if (t < 20) {
    return (x & y) ^ (x & z);
  } else if (t < 40) {
    return (x ^ y ^ z);
  } else if (t < 60) {
    return (x & y) ^ (x & z) ^ (y & z);
  } else if (t < 80) {
    return (x ^ y ^ z);
  } else {
    return -1;
  }
}

/*
** Get K constant depending on round 't'
*/
static uint32_t get_k(uint32_t t) {
  if (t < 20) {
    return K_LEVEL1;
  } else if (t < 40) {
    return K_LEVEL2;
  } else if (t < 60) {
    return K_LEVEL3;
  } else if (t < 80) {
    return K_LEVEL4;
  } else {
    return -1;
  }
}

#define WORDS_LEN 80

char *SHA1(const char *message, size_t len) {
  uint64_t i, j;
  uint32_t words[WORDS_LEN];
  char *result = (char *)malloc(HASH_SIZE);
  uint32_t h0 = H0_INIT, h1 = H1_INIT, h2 = H2_INIT, h3 = H3_INIT, h4 = H4_INIT;

  for (i = 0; i < len; i += CHUNK_SIZE) {
    uint32_t a, b, c, d, e;
    get_chunk(message + i, len - i, words);

    for (j = _SEG_LEN; j < WORDS_LEN; ++j)
      words[j] = leftrotate(
          (words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16]), 1);

    a = h0;
    b = h1;
    c = h2;
    d = h3;
    e = h4;

    for (j = 0; j < WORDS_LEN; ++j) {
      uint32_t tmp;
      tmp = leftrotate(a, 5) + func(b, c, d, j) + e + get_k(j) + words[j];
      e = d;
      d = c;
      c = leftrotate(b, 30);
      b = a;
      a = tmp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }
  build_hash(h0, h1, h2, h3, h4, result);
  return result;
}
