#ifndef GOST_H
#define GOST_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t word32;

void kboxinit(void);

void gostcrypt_reference(word32 const in[2], word32 out[2], word32 const key[8]);
void gostdecrypt_reference(word32 const in[2], word32 out[2], word32 const key[8]);

void gostcrypt(word32 const in[2], word32 out[2], word32 const key[8]);
void gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8]);

void gostofb(word32 const *in, word32 *out, int len,
             word32 const iv[2], word32 const key[8]);
void gostcfbencrypt(word32 const *in, word32 *out, int len,
                    word32 iv[2], word32 const key[8]);
void gostcfbdecrypt(word32 const *in, word32 *out, int len,
                    word32 iv[2], word32 const key[8]);
void gostmac(word32 const *in, int len, word32 out[2], word32 const key[8]);

void gostcrypt_neon_blocks(word32 const in[][2], word32 out[][2], size_t blocks,
                           word32 const key[8]);

#endif /* GOST_H */
