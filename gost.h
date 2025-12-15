#ifndef GOST_H
#define GOST_H

/*
 * Shared declarations for the GOST 28147-89 implementation.
 */
#ifdef __alpha  /* Any other 64-bit machines? */
typedef unsigned int word32;
#else
typedef unsigned long word32;
#endif

void kboxinit(void);
void gostcrypt(word32 const in[2], word32 out[2], word32 const key[8]);
void gostcrypt2(word32 const in[4], word32 out[4], word32 const key[8]);
void gostcrypt4(word32 const in[8], word32 out[8], word32 const key[8]);
void gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8]);
void gostofb(word32 const *in, word32 *out, int len,
            word32 const iv[2], word32 const key[8]);
#if defined(__ARM_NEON)
void gostofb_neon(word32 const *in, word32 *out, int len,
                 word32 const iv[2], word32 const key[8]);
void gostcrypt4_anf_neon(word32 const in[8], word32 out[8], word32 const key[8]);
#endif
void gostcfbencrypt(word32 const *in, word32 *out, int len,
                   word32 iv[2], word32 const key[8]);
void gostcfbdecrypt(word32 const *in, word32 *out, int len,
                   word32 iv[2], word32 const key[8]);
void gostmac(word32 const *in, int len, word32 out[2], word32 const key[8]);

#endif /* GOST_H */
