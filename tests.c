#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "gost.h"

static void test_known_vector(void)
{
    word32 key[8] = {0};
    word32 in[2] = {0};
    word32 out_ref[2];
    word32 out_opt[2];

    gostcrypt_reference(in, out_ref, key);
    gostcrypt(in, out_opt, key);

    assert(out_ref[0] == 0xE72B17D7u);
    assert(out_ref[1] == 0x02F122C0u);
    assert(out_ref[0] == out_opt[0]);
    assert(out_ref[1] == out_opt[1]);
}

static void test_encrypt_decrypt(void)
{
    word32 key[8];
    word32 in[2];
    word32 enc[2];
    word32 dec[2];

    for (int i = 0; i < 8; i++)
        key[i] = 0x11111111u * (unsigned)(i + 1);

    in[0] = 0x12345678u;
    in[1] = 0x9ABCDEF0u;

    gostcrypt(in, enc, key);
    gostdecrypt(enc, dec, key);

    assert(in[0] == dec[0]);
    assert(in[1] == dec[1]);
}

static void test_neon_batch_agreement(void)
{
    word32 key[8];
    word32 in[4][2];
    word32 out_scalar[4][2];
    word32 out_batch[4][2];

    for (int i = 0; i < 8; i++)
        key[i] = 0x01020304u * (unsigned)(i + 1);

    for (int i = 0; i < 4; i++) {
        in[i][0] = (word32)(0xA5A5A5A5u + i);
        in[i][1] = (word32)(0x5A5A5A5Au - i);
        gostcrypt(in[i], out_scalar[i], key);
    }

    gostcrypt_neon_blocks((const word32 (*)[2])in, out_batch, 4, key);

    for (int i = 0; i < 4; i++) {
        assert(out_scalar[i][0] == out_batch[i][0]);
        assert(out_scalar[i][1] == out_batch[i][1]);
    }
}

static void test_modes_and_mac(void)
{
    word32 key[8] = {0};
    word32 iv[2] = {0x0, 0x1};
    word32 input[4] = {0x11223344u, 0x55667788u, 0x99AABBCCu, 0xDDEEFF00u};
    word32 buffer[4];
    word32 mac[2];

    memcpy(buffer, input, sizeof(buffer));
    gostcfbencrypt(buffer, buffer, 2, iv, key);

    iv[0] = 0x0;
    iv[1] = 0x1;
    gostcfbdecrypt(buffer, buffer, 2, iv, key);
    assert(buffer[0] == input[0]);
    assert(buffer[1] == input[1]);
    assert(buffer[2] == input[2]);
    assert(buffer[3] == input[3]);

    gostmac(input, 2, mac, key);
    assert(mac[0] != 0 || mac[1] != 0);
}

int main(void)
{
    test_known_vector();
    test_encrypt_decrypt();
    test_neon_batch_agreement();
    test_modes_and_mac();

    printf("All tests passed.\n");
    return 0;
}
