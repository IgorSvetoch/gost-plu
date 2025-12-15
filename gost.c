/*
 * The GOST 28147-89 cipher
 *
 * This is based on the 25 Movember 1993 draft translation
 * by Aleksandr Malchik, with Whitfield Diffie, of the Government
 * Standard of the U.S.S.R. GOST 28149-89, "Cryptographic Transformation
 * Algorithm", effective 1 July 1990.  (Whitfield.Diffie@eng.sun.com)
 *
 * That is a draft, and may contain errors, which will be faithfully
 * reflected here, along with possible exciting new bugs.
 *
 * Some details have been cleared up by the paper "Soviet Encryption
 * Algorithm" by Josef Pieprzyk and Leonid Tombak of the University
 * of Wollongong, New South Wales.  (josef/leo@cs.adfa.oz.au)
 *
 * The standard is written by A. Zabotin (project leader), G.P. Glazkov,
 * and V.B. Isaeva.  It was accepted and introduced into use by the
 * action of the State Standards Committee of the USSR on 2 June 89 as
 * No. 1409.  It was to be reviewed in 1993, but whether anyone wishes
 * to take on this obligation from the USSR is questionable.
 *
 * This code is placed in the public domain.  Modernised and optimised
 * for ARMv7-A/NEON while keeping compatibility with the original
 * implementation.
 */

#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

/* A 32-bit data type */
typedef uint32_t word32;
typedef word32 (*gost_round_fn)(word32);

/*
 * The standard does not specify the contents of the 8 4 bit->4 bit
 * substitution boxes, saying they're a parameter of the network
 * being set up.  For illustration purposes here, I have used
 * the first rows of the 8 S-boxes from the DES.  (Note that the
 * DES S-boxes are numbered starting from 1 at the msb.  In keeping
 * with the rest of the GOST, I have used little-endian numbering.
 * Thus, k8 is S-box 1.
 *
 * Obviously, a careful look at the cryptographic properties of the cipher
 * must be undertaken before "production" substitution boxes are defined.
 *
 * The standard also does not specify a standard bit-string representation
 * for the contents of these blocks.
 */
static unsigned char const k8[16] = {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 };
static unsigned char const k7[16] = {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 };
static unsigned char const k6[16] = {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 };
static unsigned char const k5[16] = {
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 };
static unsigned char const k4[16] = {
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 };
static unsigned char const k3[16] = {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 };
static unsigned char const k2[16] = {
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 };
static unsigned char const k1[16] = {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 };

/* Byte-at-a-time substitution boxes */
static unsigned char k87[256];
static unsigned char k65[256];
static unsigned char k43[256];
static unsigned char k21[256];

/* Pre-rotated tables for the optimised F function */
static word32 f_tables[4][256];
static int kbox_ready;

static inline word32
rotl32(word32 x, unsigned bits)
{
        return (word32)((x << bits) | (x >> (32 - bits)));
}

/*
 * Build byte-at-a-time substitution tables.
 * This must be called once for global setup.
 */
void
kboxinit(void)
{
        int i;

        if (kbox_ready)
                return;

        for (i = 0; i < 256; i++) {
                k87[i] = (unsigned char)(k8[i >> 4] << 4 | k7[i & 15]);
                k65[i] = (unsigned char)(k6[i >> 4] << 4 | k5[i & 15]);
                k43[i] = (unsigned char)(k4[i >> 4] << 4 | k3[i & 15]);
                k21[i] = (unsigned char)(k2[i >> 4] << 4 | k1[i & 15]);
        }

        /* Precompute rotated contributions for each byte position */
        for (i = 0; i < 256; i++) {
                word32 base;

                base = (word32)k87[i] << 24;
                f_tables[0][i] = rotl32(base, 11);

                base = (word32)k65[i] << 16;
                f_tables[1][i] = rotl32(base, 11);

                base = (word32)k43[i] << 8;
                f_tables[2][i] = rotl32(base, 11);

                base = (word32)k21[i];
                f_tables[3][i] = rotl32(base, 11);
        }

        kbox_ready = 1;
}

/* Reference F function using the lookup tables */
static inline word32
f_reference(word32 x)
{
        /* This is faster than nibble-at-a-time substitution */
        x = (word32)k87[x >> 24 & 255] << 24 | (word32)k65[x >> 16 & 255] << 16 |
            (word32)k43[x >> 8 & 255] << 8 | (word32)k21[x & 255];

        /* Rotate left 11 bits */
        return rotl32(x, 11);
}

/* Optimised F using pre-rotated per-byte tables */
static inline word32
f_fast(word32 x)
{
        return f_tables[0][x >> 24] ^ f_tables[1][(x >> 16) & 255] ^
               f_tables[2][(x >> 8) & 255] ^ f_tables[3][x & 255];
}

#define TWO_ROUNDS(k1, k2, f_fn)                     \
        n2 ^= f_fn(n1 + key[k1]);                    \
        n1 ^= f_fn(n2 + key[k2]);

static void
_gostcrypt(word32 const in[2], word32 out[2], word32 const key[8], gost_round_fn f_fn)
{
        word32 n1, n2;

        n1 = in[0];
        n2 = in[1];

        /* Three forward key passes */
        for (int round = 0; round < 3; round++) {
                TWO_ROUNDS(0, 1, f_fn);
                TWO_ROUNDS(2, 3, f_fn);
                TWO_ROUNDS(4, 5, f_fn);
                TWO_ROUNDS(6, 7, f_fn);
        }

        /* One reverse key pass */
        n2 ^= f_fn(n1 + key[7]);
        n1 ^= f_fn(n2 + key[6]);
        n2 ^= f_fn(n1 + key[5]);
        n1 ^= f_fn(n2 + key[4]);
        n2 ^= f_fn(n1 + key[3]);
        n1 ^= f_fn(n2 + key[2]);
        n2 ^= f_fn(n1 + key[1]);
        n1 ^= f_fn(n2 + key[0]);

        /* There is no swap after the last round */
        out[0] = n2;
        out[1] = n1;
}

static void
_gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8], gost_round_fn f_fn)
{
        word32 n1, n2;

        n1 = in[0];
        n2 = in[1];

        /* First reverse key pass */
        n2 ^= f_fn(n1 + key[0]);
        n1 ^= f_fn(n2 + key[1]);
        n2 ^= f_fn(n1 + key[2]);
        n1 ^= f_fn(n2 + key[3]);
        n2 ^= f_fn(n1 + key[4]);
        n1 ^= f_fn(n2 + key[5]);
        n2 ^= f_fn(n1 + key[6]);
        n1 ^= f_fn(n2 + key[7]);

        /* Three forward passes */
        for (int round = 0; round < 3; round++) {
                n2 ^= f_fn(n1 + key[7]);
                n1 ^= f_fn(n2 + key[6]);
                n2 ^= f_fn(n1 + key[5]);
                n1 ^= f_fn(n2 + key[4]);
                n2 ^= f_fn(n1 + key[3]);
                n1 ^= f_fn(n2 + key[2]);
                n2 ^= f_fn(n1 + key[1]);
                n1 ^= f_fn(n2 + key[0]);
        }

        out[0] = n2;
        out[1] = n1;
}

void
gostcrypt_reference(word32 const in[2], word32 out[2], word32 const key[8])
{
        kboxinit();
        _gostcrypt(in, out, key, f_reference);
}

void
gostdecrypt_reference(word32 const in[2], word32 out[2], word32 const key[8])
{
        kboxinit();
        _gostdecrypt(in, out, key, f_reference);
}

void
gostcrypt(word32 const in[2], word32 out[2], word32 const key[8])
{
        kboxinit();
        _gostcrypt(in, out, key, f_fast);
}

void
gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8])
{
        kboxinit();
        _gostdecrypt(in, out, key, f_fast);
}

void
gostofb(word32 const *in, word32 *out, int len,
        word32 const iv[2], word32 const key[8])
{
        word32 temp[2];         /* Counter */
        word32 gamma[2];        /* Output XOR value */

        /* Compute starting value for counter */
        gostcrypt(iv, temp, key);

        while (len--) {
                temp[0] += 0x01010101U;
                if (temp[0] < 0x01010101U)       /* Wrap modulo 2^32? */
                        temp[0]++;      /* Make it modulo 2^32-1 */
                temp[1] += 0x01010104U;
                if (temp[1] < 0x01010104U)       /* Wrap modulo 2^32? */
                        temp[1]++;      /* Make it modulo 2^32-1 */

                gostcrypt(temp, gamma, key);

                *out++ = *in++ ^ gamma[0];
                *out++ = *in++ ^ gamma[1];
        }
}

void
gostcfbencrypt(word32 const *in, word32 *out, int len,
               word32 iv[2], word32 const key[8])
{
        (void)in;
        while (len--) {
                gostcrypt(iv, iv, key);
                iv[0] = *out++ ^= iv[0];
                iv[1] = *out++ ^= iv[1];
        }
}

void
gostcfbdecrypt(word32 const *in, word32 *out, int len,
               word32 iv[2], word32 const key[8])
{
        word32 t;
        (void)in;
        while (len--) {
                gostcrypt(iv, iv, key);
                t = *out;
                *out++ ^= iv[0];
                iv[0] = t;
                t = *out;
                *out++ ^= iv[1];
                iv[1] = t;
        }
}

void
gostmac(word32 const *in, int len, word32 out[2], word32 const key[8])
{
        word32 n1, n2; /* As named in the GOST */

        kboxinit();

        n1 = 0;
        n2 = 0;

        while (len--) {
                n1 ^= *in++;
                n2 = *in++;

                /* Instead of swapping halves, swap names each round */
                n2 ^= f_fast(n1 + key[0]);
                n1 ^= f_fast(n2 + key[1]);
                n2 ^= f_fast(n1 + key[2]);
                n1 ^= f_fast(n2 + key[3]);
                n2 ^= f_fast(n1 + key[4]);
                n1 ^= f_fast(n2 + key[5]);
                n2 ^= f_fast(n1 + key[6]);
                n1 ^= f_fast(n2 + key[7]);

                n2 ^= f_fast(n1 + key[0]);
                n1 ^= f_fast(n2 + key[1]);
                n2 ^= f_fast(n1 + key[2]);
                n1 ^= f_fast(n2 + key[3]);
                n2 ^= f_fast(n1 + key[4]);
                n1 ^= f_fast(n2 + key[5]);
                n2 ^= f_fast(n1 + key[6]);
                n1 ^= f_fast(n2 + key[7]);
        }

        out[0] = n1;
        out[1] = n2;
}

#if defined(__ARM_NEON__)
static inline void
_store_block(uint32x4_t v, word32 out[][2], size_t offset)
{
        out[offset][0] = vgetq_lane_u32(v, 0);
        out[offset + 1][0] = vgetq_lane_u32(v, 1);
        out[offset + 2][0] = vgetq_lane_u32(v, 2);
        out[offset + 3][0] = vgetq_lane_u32(v, 3);
}

static inline void
_store_block_n2(uint32x4_t v, word32 out[][2], size_t offset)
{
        out[offset][1] = vgetq_lane_u32(v, 0);
        out[offset + 1][1] = vgetq_lane_u32(v, 1);
        out[offset + 2][1] = vgetq_lane_u32(v, 2);
        out[offset + 3][1] = vgetq_lane_u32(v, 3);
}
#endif

/*
 * Encrypt up to four blocks at a time using NEON.  The F function stays
 * scalar (because the S-box is table-based) but additions and XORs are
 * vectorised, which yields a measurable speed-up on Cortex-A9.
 */
void
gostcrypt_neon_blocks(word32 const in[][2], word32 out[][2], size_t blocks,
                        word32 const key[8])
{
        kboxinit();

#if defined(__ARM_NEON__)
        size_t i = 0;
        for (; i + 3 < blocks; i += 4) {
                uint32x4_t n1 = { in[i][0], in[i + 1][0], in[i + 2][0], in[i + 3][0] };
                uint32x4_t n2 = { in[i][1], in[i + 1][1], in[i + 2][1], in[i + 3][1] };
                uint32_t tmp[4];
                uint32x4_t fvec;

#define NEON_TWO_ROUNDS(k1, k2)                                                \
                do {                                                           \
                        uint32x4_t sum = vaddq_u32(n1, vdupq_n_u32(key[k1])); \
                        vst1q_u32(tmp, sum);                                  \
                        tmp[0] = f_fast(tmp[0]);                               \
                        tmp[1] = f_fast(tmp[1]);                               \
                        tmp[2] = f_fast(tmp[2]);                               \
                        tmp[3] = f_fast(tmp[3]);                               \
                        fvec = vld1q_u32(tmp);                                 \
                        n2 = veorq_u32(n2, fvec);                              \
                        sum = vaddq_u32(n2, vdupq_n_u32(key[k2]));             \
                        vst1q_u32(tmp, sum);                                  \
                        tmp[0] = f_fast(tmp[0]);                               \
                        tmp[1] = f_fast(tmp[1]);                               \
                        tmp[2] = f_fast(tmp[2]);                               \
                        tmp[3] = f_fast(tmp[3]);                               \
                        fvec = vld1q_u32(tmp);                                 \
                        n1 = veorq_u32(n1, fvec);                              \
                } while (0)

                for (int round = 0; round < 3; round++) {
                        NEON_TWO_ROUNDS(0, 1);
                        NEON_TWO_ROUNDS(2, 3);
                        NEON_TWO_ROUNDS(4, 5);
                        NEON_TWO_ROUNDS(6, 7);
                }

                /* Reverse pass */
                {
                        uint32x4_t sum = vaddq_u32(n1, vdupq_n_u32(key[7]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n2 = veorq_u32(n2, fvec);

                        sum = vaddq_u32(n2, vdupq_n_u32(key[6]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n1 = veorq_u32(n1, fvec);

                        sum = vaddq_u32(n1, vdupq_n_u32(key[5]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n2 = veorq_u32(n2, fvec);

                        sum = vaddq_u32(n2, vdupq_n_u32(key[4]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n1 = veorq_u32(n1, fvec);

                        sum = vaddq_u32(n1, vdupq_n_u32(key[3]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n2 = veorq_u32(n2, fvec);

                        sum = vaddq_u32(n2, vdupq_n_u32(key[2]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n1 = veorq_u32(n1, fvec);

                        sum = vaddq_u32(n1, vdupq_n_u32(key[1]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n2 = veorq_u32(n2, fvec);

                        sum = vaddq_u32(n2, vdupq_n_u32(key[0]));
                        vst1q_u32(tmp, sum);
                        tmp[0] = f_fast(tmp[0]);
                        tmp[1] = f_fast(tmp[1]);
                        tmp[2] = f_fast(tmp[2]);
                        tmp[3] = f_fast(tmp[3]);
                        fvec = vld1q_u32(tmp);
                        n1 = veorq_u32(n1, fvec);
                }

#undef NEON_TWO_ROUNDS
                _store_block(n2, out, i);
                _store_block_n2(n1, out, i);
        }

        /* Handle any remaining blocks */
        for (; i < blocks; i++)
                gostcrypt(&in[i][0], &out[i][0], key);
#else
        for (size_t i = 0; i < blocks; i++)
                gostcrypt(&in[i][0], &out[i][0], key);
#endif
}

