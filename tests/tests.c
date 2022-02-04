#include "../src/sha1.c"
#include "sha1.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
    printf("%x\n", words[0]);
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

int main() {
  int i;
  test_func tests[] = {
      test_leftrotate,
      test_get_chunk,
  };
  char *test_names[] = {"leftrotate", "get_chunck"};

  size_t tests_count = sizeof(tests) / sizeof(*tests);
  for (i = 0; i < tests_count; ++i) {
    if (tests[i]()) {
      printf("TEST '%s' %d OK\n", test_names[i], i + 1);
    } else {
      printf("TEST '%s' %d FAIL\n", test_names[i], i + 1);
      return 0;
    }
  }

  char mess[] = "abc";
  char *res = SHA1(mess);
  for (int i = 0; i < HASH_SIZE; ++i) {
    printf("%02hhX", res[i]);
  }
  putchar('\n');
  free(res);
  return 0;
}
