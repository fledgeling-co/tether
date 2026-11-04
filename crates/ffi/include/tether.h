#ifndef TETHER_H
#define TETHER_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Request must be readable UTF-8 of length <=131072. Result is an owned UTF-8 JSON C string.
 * Always call tether_free exactly once; it wipes the returned buffer before releasing it.
 * Neither requests nor responses may be logged: identity operations carry private keys. */
char *tether_call(const unsigned char *request_utf8, size_t length);
void tether_free(char *response);
#ifdef __cplusplus
}
#endif
#endif
