#include "../src/sha1.c"
#include "sha1.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef bool (*test_func)();

/* TEST leftrotate */
bool test_leftrotate() {
  int i;
  uint32_t test_vals[][3] = {
      {1 | (1 << 1), 1, (1 << 2) | (1 << 1)},
      {(1 << 1) | (1 << 31), 1, (1 << 2) | (1)},
  };

  for (i = 0; i < 2; ++i) {
    if (leftrotate(test_vals[i][0], test_vals[i][1]) != test_vals[i][2])
      return false;
  }

  return true;
}

/* TEST get_chunck */
bool test_get_chunk() {
  char test_mess[] = {
      0x16, 0x16, 0x16, 0x16, 0x17, 0x17, 0x17, 0x17,
      0x18, 0x18, 0x18, 0x18, 0x19, 0x19, 0x19, 0x19,
  };
  uint32_t words[WORDS_LEN];
  get_chunk(test_mess, sizeof(test_mess), words);
  if (words[0] != 0x16161616) {
    return false;
  }
  if (words[1] != 0x17171717) {
    return false;
  }
  if (words[2] != 0x18181818) {
    return false;
  }
  return true;
}

/*
**
20 8D 02 30 5E 38 0E 00 20 44 9A 07 20 FA 8E 7C 09 20 B8 46
00 68 4E C2 79 EF 38 12 5D 28 B2 BA 00 49 BB 14 23 40 A2 8C
*/

bool test_sha1() {
  int i;
  char mess[] = "abc";
  char *res = SHA1(mess, strlen(mess));
  char res_test[] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81,
                     0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                     0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};

  /* compare arrays */
  bool flag = true;
  for (i = 0; i < HASH_SIZE; ++i)
    if (res[i] != res_test[i]) {
      flag = false;
      break;
    }

  if (!flag) {
    for (i = 0; i < HASH_SIZE; ++i)
      printf("%02hhX ", res[i]);
    putchar('\n');

    for (i = 0; i < HASH_SIZE; ++i)
      printf("%02hhX ", res_test[i]);
    putchar('\n');
    return false;
  }

  free(res);
  return true;
}

int main() {
  int i;
  test_func tests[] = {
      test_leftrotate,
      test_get_chunk,
      test_sha1,
  };
  char *test_names[] = {"leftrotate", "get_chunck", "sha1"};

  size_t tests_count = sizeof(tests) / sizeof(*tests);
  for (i = 0; i < tests_count; ++i) {
    if (tests[i]()) {
      printf("TEST '%s' %d OK\n", test_names[i], i + 1);
    } else {
      printf("TEST '%s' %d FAIL\n", test_names[i], i + 1);
      return 0;
    }
  }

  return 0;
}
