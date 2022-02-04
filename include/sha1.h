#ifndef SHA1_H_SENTRY
#define SHA1_H_SENTRY

#include <stddef.h>

const size_t HASH_SIZE = 20; /* size of returned SHA1 value in bytes */

/* Hash-function that will create a hash( an array
 * of bytes with HASH_SIZE size ) from input string.
 *
 * return value will be allocated inside.  */
char *SHA1(const char *message);

#endif // SHA1_H_SENTRY
