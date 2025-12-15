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

typedef struct {
        word32 enc_key[32];
        word32 dec_key[32];
} gost_ctx;

void gost_init(gost_ctx *ctx, word32 const key[8]);
void gost_encrypt_block(gost_ctx const *ctx, word32 const in[2], word32 out[2]);
void gost_decrypt_block(gost_ctx const *ctx, word32 const in[2], word32 out[2]);

void kboxinit(void);
void gostcrypt(word32 const in[2], word32 out[2], word32 const key[8]);
void gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8]);
void gostofb(word32 const *in, word32 *out, int len,
            word32 const iv[2], word32 const key[8]);
void gostcfbencrypt(word32 const *in, word32 *out, int len,
                   word32 iv[2], word32 const key[8]);
void gostcfbdecrypt(word32 const *in, word32 *out, int len,
                   word32 iv[2], word32 const key[8]);
void gostmac(word32 const *in, int len, word32 out[2], word32 const key[8]);

#endif /* GOST_H */
