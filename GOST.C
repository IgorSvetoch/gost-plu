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
 * This code is placed in the public domain.
 */

/*
 * If you read the standard, it belabors the point of copying corresponding
 * bits from point A to point B quite a bit.  It helps to understand that
 * the standard is uniformly little-endian, although it numbers bits from
 * 1 rather than 0, so bit n has value 2^(n-1).  The least significant bit
 * of the 32-bit words that are manipulated in the algorithm is the first,
 * lowest-numbered, in the bit string.
 */


#include "gost.h"

#if defined(__ARM_NEON)
#include <arm_neon.h>
#include <stdint.h>
#endif

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
static word32 T0[256];
static word32 T1[256];
static word32 T2[256];
static word32 T3[256];
#if defined(__ARM_NEON)
static uint16_t const sbox_anf[8][4] = {
        {0x091f, 0x013a, 0x1f27, 0x4e53},
        {0x11da, 0x091e, 0x1507, 0x5492},
        {0x54d2, 0x3824, 0x05b7, 0x11cb},
        {0x26b8, 0x6bef, 0x0416, 0x0dca},
        {0x1a1d, 0x419b, 0x5139, 0x3a26},
        {0x012c, 0x5fe7, 0x7638, 0x6d7b},
        {0x2835, 0x01e7, 0x1507, 0x1c1b},
        {0x0b24, 0x766f, 0x0d39, 0x51d3},
};
#endif

static inline word32 rotl32(word32 x, unsigned n)
{
        return (x << n) | (x >> (32 - n));
}

/*
 * Build byte-at-a-time subtitution tables.
 * This must be called once for global setup.
 */
void
kboxinit(void)
{
        int i;
        for (i = 0; i < 256; i++) {
                k87[i] = k8[i >> 4] << 4 | k7[i & 15];
                k65[i] = k6[i >> 4] << 4 | k5[i & 15];
                k43[i] = k4[i >> 4] << 4 | k3[i & 15];
                k21[i] = k2[i >> 4] << 4 | k1[i & 15];

                {
                        word32 b0 = k21[i];
                        word32 b1 = k43[i];
                        word32 b2 = k65[i];
                        word32 b3 = k87[i];

                        T0[i] = rotl32(b0, 11);
                        T1[i] = rotl32(b1 << 8, 11);
                        T2[i] = rotl32(b2 << 16, 11);
                        T3[i] = rotl32(b3 << 24, 11);
                }
        }
}

/*
 * Do the substitution and rotation that are the core of the operation,
 * like the expansion, substitution and permutation of the DES.
 * We precompute 32-bit tables with the S-box output already rotated
 * into place to minimise shifts and bitwise OR operations at runtime.
 *
 * This should be inlined for maximum speed
 */
#if __GNUC__
__inline__
#endif
static word32
f(word32 x)
{
        return T0[(unsigned char)(x      )] ^
               T1[(unsigned char)(x >>  8)] ^
               T2[(unsigned char)(x >> 16)] ^
               T3[(unsigned char)(x >> 24)];
}

#if defined(__ARM_NEON)
static inline uint32x4_t
vxor_u32(uint32x4_t a, uint32x4_t b)
{
return veorq_u32(a, b);
}

static inline uint32x4_t
vandq_u32_safe(uint32x4_t a, uint32x4_t b)
{
return vandq_u32(a, b);
}

static inline uint32x4_t
vshr_u32(uint32x4_t x, int n)
{
        return vshlq_u32(x, vdupq_n_s32(-n));
}

static inline uint32x4_t
vshl_u32(uint32x4_t x, int n)
{
        return vshlq_u32(x, vdupq_n_s32(n));
}

static inline uint32x4_t
vrotl32_u32(uint32x4_t x, int n)
{
        return vorrq_u32(vshl_u32(x, n), vshr_u32(x, 32 - n));
}

static inline void
sbox4_anf_u32x4(uint32x4_t a0, uint32x4_t a1, uint32x4_t a2, uint32x4_t a3,
               uint16_t const c[4], uint32x4_t *y0, uint32x4_t *y1,
               uint32x4_t *y2, uint32x4_t *y3)
{
        uint32x4_t const one = vdupq_n_u32(1);
        uint32x4_t m0 = one;
        uint32x4_t m1 = a0;
        uint32x4_t m2 = a1;
uint32x4_t m3 = vandq_u32_safe(a0, a1);
uint32x4_t m4 = a2;
uint32x4_t m5 = vandq_u32_safe(a0, a2);
uint32x4_t m6 = vandq_u32_safe(a1, a2);
uint32x4_t m7 = vandq_u32_safe(m3, a2);
uint32x4_t m8 = a3;
uint32x4_t m9 = vandq_u32_safe(a0, a3);
uint32x4_t m10 = vandq_u32_safe(a1, a3);
uint32x4_t m11 = vandq_u32_safe(m3, a3);
uint32x4_t m12 = vandq_u32_safe(a2, a3);
uint32x4_t m13 = vandq_u32_safe(m5, a3);
uint32x4_t m14 = vandq_u32_safe(m6, a3);
uint32x4_t m15 = vandq_u32_safe(m7, a3);

        uint32x4_t const monomials[16] = {
                m0, m1, m2, m3, m4, m5, m6, m7,
                m8, m9, m10, m11, m12, m13, m14, m15,
        };

        uint32x4_t out0 = vdupq_n_u32(0);
        uint32x4_t out1 = vdupq_n_u32(0);
        uint32x4_t out2 = vdupq_n_u32(0);
        uint32x4_t out3 = vdupq_n_u32(0);

        for (int ob = 0; ob < 4; ++ob) {
                uint16_t mask = c[ob];
                uint32x4_t acc = vdupq_n_u32(0);
                for (int t = 0; t < 16; ++t) {
                        if (mask & (1u << t))
                                acc = vxor_u32(acc, monomials[t]);
                }

                switch (ob) {
                case 0:
                        out0 = acc;
                        break;
                case 1:
                        out1 = acc;
                        break;
                case 2:
                        out2 = acc;
                        break;
                default:
                        out3 = acc;
                        break;
                }
        }

        *y0 = out0;
        *y1 = out1;
        *y2 = out2;
        *y3 = out3;
}

static inline uint32x4_t
f_anf4(uint32x4_t x)
{
        uint32x4_t const one = vdupq_n_u32(1);
        uint32x4_t r = vdupq_n_u32(0);

for (int p = 0; p < 8; ++p) {
int base = 4 * p;
uint32x4_t a0 = vandq_u32_safe(vshr_u32(x, base + 0), one);
uint32x4_t a1 = vandq_u32_safe(vshr_u32(x, base + 1), one);
uint32x4_t a2 = vandq_u32_safe(vshr_u32(x, base + 2), one);
uint32x4_t a3 = vandq_u32_safe(vshr_u32(x, base + 3), one);

                uint32x4_t y0, y1, y2, y3;
                sbox4_anf_u32x4(a0, a1, a2, a3, sbox_anf[p], &y0, &y1, &y2,
                                &y3);

                uint32x4_t ny =
                    vxor_u32(vxor_u32(y0, vshl_u32(y1, 1)),
                             vxor_u32(vshl_u32(y2, 2), vshl_u32(y3, 3)));
                r = vxor_u32(r, vshl_u32(ny, base));
        }

        return vrotl32_u32(r, 11);
}
#endif

#define GOST_ROUND_PAIR(n1_a, n2_a, n1_b, n2_b, key_a, key_b) \
        do { \
                (n2_a) ^= f((n1_a) + (key_a)); \
                (n2_b) ^= f((n1_b) + (key_a)); \
                (n1_a) ^= f((n2_a) + (key_b)); \
                (n1_b) ^= f((n2_b) + (key_b)); \
        } while (0)

#define GOST_ROUND_QUAD(n1_a, n2_a, n1_b, n2_b, n1_c, n2_c, n1_d, n2_d, key_a, key_b) \
        do { \
                (n2_a) ^= f((n1_a) + (key_a)); \
                (n2_b) ^= f((n1_b) + (key_a)); \
                (n2_c) ^= f((n1_c) + (key_a)); \
                (n2_d) ^= f((n1_d) + (key_a)); \
                (n1_a) ^= f((n2_a) + (key_b)); \
                (n1_b) ^= f((n2_b) + (key_b)); \
                (n1_c) ^= f((n2_c) + (key_b)); \
                (n1_d) ^= f((n2_d) + (key_b)); \
        } while (0)

/*
 * The GOST standard defines the input in terms of bits 1..64, with
 * bit 1 being the lsb of in[0] and bit 64 being the msb of in[1].
 *
 * The keys are defined similarly, with bit 256 being the msb of key[7].
 */
void
gostcrypt(word32 const in[2], word32 out[2], word32 const key[8])
{
        register word32 n1, n2; /* As named in the GOST */

	n1 = in[0];
	n2 = in[1];

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(n1+key[0]);
	n1 ^= f(n2+key[1]);
	n2 ^= f(n1+key[2]);
	n1 ^= f(n2+key[3]);
	n2 ^= f(n1+key[4]);
	n1 ^= f(n2+key[5]);
	n2 ^= f(n1+key[6]);
	n1 ^= f(n2+key[7]);

	n2 ^= f(n1+key[0]);
	n1 ^= f(n2+key[1]);
	n2 ^= f(n1+key[2]);
	n1 ^= f(n2+key[3]);
	n2 ^= f(n1+key[4]);
	n1 ^= f(n2+key[5]);
	n2 ^= f(n1+key[6]);
	n1 ^= f(n2+key[7]);

	n2 ^= f(n1+key[0]);
	n1 ^= f(n2+key[1]);
	n2 ^= f(n1+key[2]);
	n1 ^= f(n2+key[3]);
	n2 ^= f(n1+key[4]);
	n1 ^= f(n2+key[5]);
	n2 ^= f(n1+key[6]);
	n1 ^= f(n2+key[7]);

	n2 ^= f(n1+key[7]);
	n1 ^= f(n2+key[6]);
	n2 ^= f(n1+key[5]);
	n1 ^= f(n2+key[4]);
	n2 ^= f(n1+key[3]);
	n1 ^= f(n2+key[2]);
	n2 ^= f(n1+key[1]);
	n1 ^= f(n2+key[0]);

        /* There is no swap after the last round */
        out[0] = n2;
        out[1] = n1;
}

void
gostcrypt2(word32 const in[4], word32 out[4], word32 const key[8])
{
        register word32 n1_0 = in[0];
        register word32 n2_0 = in[1];
        register word32 n1_1 = in[2];
        register word32 n2_1 = in[3];

        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[0], key[1]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[2], key[3]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[4], key[5]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[6], key[7]);

        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[0], key[1]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[2], key[3]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[4], key[5]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[6], key[7]);

        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[0], key[1]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[2], key[3]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[4], key[5]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[6], key[7]);

        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[7], key[6]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[5], key[4]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[3], key[2]);
        GOST_ROUND_PAIR(n1_0, n2_0, n1_1, n2_1, key[1], key[0]);

        out[0] = n2_0;
        out[1] = n1_0;
        out[2] = n2_1;
        out[3] = n1_1;
}

void
gostcrypt4(word32 const in[8], word32 out[8], word32 const key[8])
{
        register word32 n1_0 = in[0];
        register word32 n2_0 = in[1];
        register word32 n1_1 = in[2];
        register word32 n2_1 = in[3];
        register word32 n1_2 = in[4];
        register word32 n2_2 = in[5];
        register word32 n1_3 = in[6];
        register word32 n2_3 = in[7];

        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[0], key[1]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[2], key[3]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[4], key[5]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[6], key[7]);

        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[0], key[1]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[2], key[3]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[4], key[5]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[6], key[7]);

        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[0], key[1]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[2], key[3]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[4], key[5]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[6], key[7]);

        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[7], key[6]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[5], key[4]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[3], key[2]);
        GOST_ROUND_QUAD(n1_0, n2_0, n1_1, n2_1, n1_2, n2_2, n1_3, n2_3, key[1], key[0]);

        out[0] = n2_0;
        out[1] = n1_0;
        out[2] = n2_1;
        out[3] = n1_1;
        out[4] = n2_2;
        out[5] = n1_2;
        out[6] = n2_3;
        out[7] = n1_3;
}

#if defined(__ARM_NEON)
void
gostcrypt4_anf_neon(word32 const in[8], word32 out[8], word32 const key[8])
{
        uint32x4_t n1 = vld1q_u32((uint32_t const *)in);
        uint32x4_t n2 = vld1q_u32((uint32_t const *)(in + 4));

        for (int i = 0; i < 24; ++i) {
                uint32x4_t k = vdupq_n_u32((uint32_t)key[i & 7]);
                uint32x4_t t = vaddq_u32(n1, k);
                t = f_anf4(t);
                t = veorq_u32(t, n2);
                n2 = n1;
                n1 = t;
        }
        for (int i = 7; i >= 0; --i) {
                uint32x4_t k = vdupq_n_u32((uint32_t)key[i]);
                uint32x4_t t = vaddq_u32(n1, k);
                t = f_anf4(t);
                t = veorq_u32(t, n2);
                n2 = n1;
                n1 = t;
        }

        vst1q_u32((uint32_t *)out, n2);
        vst1q_u32((uint32_t *)(out + 4), n1);
}
#endif
	

/*
 * The key schedule is somewhat different for decryption.
 * (The key table is used once forward and three times backward.)
 * You could define an expanded key, or just write the code twice,
 * as done here.
 */
void
gostdecrypt(word32 const in[2], word32 out[2], word32 const key[8])
{
	register word32 n1, n2; /* As named in the GOST */

	n1 = in[0];
	n2 = in[1];

	n2 ^= f(n1+key[0]);
	n1 ^= f(n2+key[1]);
	n2 ^= f(n1+key[2]);
	n1 ^= f(n2+key[3]);
	n2 ^= f(n1+key[4]);
	n1 ^= f(n2+key[5]);
	n2 ^= f(n1+key[6]);
	n1 ^= f(n2+key[7]);

	n2 ^= f(n1+key[7]);
	n1 ^= f(n2+key[6]);
	n2 ^= f(n1+key[5]);
	n1 ^= f(n2+key[4]);
	n2 ^= f(n1+key[3]);
	n1 ^= f(n2+key[2]);
	n2 ^= f(n1+key[1]);
	n1 ^= f(n2+key[0]);

	n2 ^= f(n1+key[7]);
	n1 ^= f(n2+key[6]);
	n2 ^= f(n1+key[5]);
	n1 ^= f(n2+key[4]);
	n2 ^= f(n1+key[3]);
	n1 ^= f(n2+key[2]);
	n2 ^= f(n1+key[1]);
	n1 ^= f(n2+key[0]);

	n2 ^= f(n1+key[7]);
	n1 ^= f(n2+key[6]);
	n2 ^= f(n1+key[5]);
	n1 ^= f(n2+key[4]);
	n2 ^= f(n1+key[3]);
	n1 ^= f(n2+key[2]);
	n2 ^= f(n1+key[1]);
	n1 ^= f(n2+key[0]);

	out[0] = n2;
	out[1] = n1;
}

/*
 * The GOST "Output feedback" standard.  It seems closer morally
 * to the counter feedback mode some people have proposed for DES.
 * The avoidance of the short cycles that are possible in OFB seems
 * like a Good Thing.
 *
 * Calling it the stream mode makes more sense.
 *
 * The IV is encrypted with the key to produce the initial counter value.
 * Then, for each output block, a constant is added, modulo 2^32-1
 * (0 is represented as all-ones, not all-zeros), to each half of
 * the counter, and the counter is encrypted to produce the value
 * to XOR with the output.
 *
 * Len is the number of blocks.  Sub-block encryption is
 * left as an exercise for the user.  Remember that the
 * standard defines everything in a little-endian manner,
 * so you want to use the low bit of gamma[0] first.
 *
 * OFB is, of course, self-inverse, so there is only one function.
 */

/* The constants for addition */
#define C1 0x01010104
#define C2 0x01010101

void
gostofb(word32 const *in, word32 *out, int len,
        word32 const iv[2], word32 const key[8])
{
        word32 temp[2];         /* Counter */
	word32 gamma[2];        /* Output XOR value */

	/* Compute starting value for counter */
	gostcrypt(iv, temp, key);

	while (len--) {
		temp[0] += C2;
		if (temp[0] < C2)       /* Wrap modulo 2^32? */
			temp[0]++;      /* Make it modulo 2^32-1 */
		temp[1] += C1;
		if (temp[1] < C1)       /* Wrap modulo 2^32? */
			temp[1]++;      /* Make it modulo 2^32-1 */

		gostcrypt(temp, gamma, key);

                *out++ = *in++ ^ gamma[0];
                *out++ = *in++ ^ gamma[1];
        }
}

#if defined(__ARM_NEON)
void
gostofb_neon(word32 const *in, word32 *out, int len,
            word32 const iv[2], word32 const key[8])
{
        word32 temp[2];         /* Counter */
        word32 gamma[8];        /* Four output blocks */

        /* Compute starting value for counter */
        gostcrypt(iv, temp, key);

        while (len >= 4) {
                for (int i = 0; i < 4; ++i) {
                        temp[0] += C2;
                        if (temp[0] < C2)
                                temp[0]++;
                        temp[1] += C1;
                        if (temp[1] < C1)
                                temp[1]++;

                        gostcrypt(temp, &gamma[2 * i], key);
                }

                uint32x4_t in0 = vld1q_u32((uint32_t const *)in);
                uint32x4_t in1 = vld1q_u32((uint32_t const *)(in + 4));

                uint32x4_t g0 = vld1q_u32((uint32_t const *)gamma);
                uint32x4_t g1 = vld1q_u32((uint32_t const *)(gamma + 4));

                uint32x4_t out0 = veorq_u32(in0, g0);
                uint32x4_t out1 = veorq_u32(in1, g1);

                vst1q_u32((uint32_t *)out, out0);
                vst1q_u32((uint32_t *)(out + 4), out1);

                in += 8;
                out += 8;
                len -= 4;
        }

        while (len--) {
                temp[0] += C2;
                if (temp[0] < C2)
                        temp[0]++;
                temp[1] += C1;
                if (temp[1] < C1)
                        temp[1]++;

                gostcrypt(temp, gamma, key);

                *out++ = *in++ ^ gamma[0];
                *out++ = *in++ ^ gamma[1];
        }
}
#endif

/*
 * The CFB mode is just what you'd expect.  Each block of ciphertext y[] is
 * derived from the input x[] by the following pseudocode:
 * y[i] = x[i] ^ gostcrypt(y[i-1])
 * x[i] = y[i] ^ gostcrypt(y[i-1])
 * Where y[-1] is the IV.
 *
 * The IV is modified in place.  Again, len is in *blocks*.
 */

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
        (void)in;
        word32 t;
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


/*
 * The message suthetication code uses only 16 of the 32 rounds.
 * There *is* a swap after the 16th round.
 * The last block should be padded to 64 bits with zeros.
 * len is the number of *blocks* in the input.
 */
void
gostmac(word32 const *in, int len, word32 out[2], word32 const key[8])
{
	register word32 n1, n2; /* As named in the GOST */

	n1 = 0;
	n2 = 0;

	while (len--) {
		n1 ^= *in++;
		n2 = *in++;

		/* Instead of swapping halves, swap names each round */
		n2 ^= f(n1+key[0]);
		n1 ^= f(n2+key[1]);
		n2 ^= f(n1+key[2]);
		n1 ^= f(n2+key[3]);
		n2 ^= f(n1+key[4]);
		n1 ^= f(n2+key[5]);
		n2 ^= f(n1+key[6]);
		n1 ^= f(n2+key[7]);

		n2 ^= f(n1+key[0]);
		n1 ^= f(n2+key[1]);
		n2 ^= f(n1+key[2]);
		n1 ^= f(n2+key[3]);
		n2 ^= f(n1+key[4]);
		n1 ^= f(n2+key[5]);
		n2 ^= f(n1+key[6]);
		n1 ^= f(n2+key[7]);
	}

	out[0] = n1;
	out[1] = n2;
}

#ifdef TEST

#include <stdio.h>
#include <stdlib.h>

/* Designed to cope with 15-bit rand() implementations */
#define RAND32 ((word32)rand() << 17 ^ (word32)rand() << 9 ^ rand())

int
main(void)
{
	word32 key[8];
	word32 plain[2];
	word32 cipher[2];
	int i, j;

	kboxinit();

	printf("GOST 21847-89 test driver.\n");

	for (i = 0; i < 1000; i++) {
		for (j = 0; j < 8; j++)
			key[j] = RAND32;
		plain[0] = RAND32;
		plain[1] = RAND32;

		printf("%3d\r", i);
		fflush(stdout);

		gostcrypt(plain, cipher, key);
		for (j = 0; j < 99; j++)
			gostcrypt(cipher, cipher, key);
		for (j = 0; j < 100; j++)
			gostdecrypt(cipher, cipher, key);

		if (plain[0] != cipher[0] || plain[1] != cipher[1]) {
			fprintf(stderr, "\nError! i = %d\n", i);
			return 1;
		}
	}
	printf("All tests passed.\n");
	return 0;
}

#endif /* TEST */

