#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "gost.h"

static void fill_buffer(word32 *data, size_t blocks)
{
        /* Use a simple LCG to keep the data deterministic across runs. */
        unsigned long seed = 0x1db71064UL;
        for (size_t i = 0; i < blocks * 2; i++) {
                seed = seed * 1664525UL + 1013904223UL;
                data[i] = (word32)seed;
        }
}

static double elapsed_seconds(struct timespec start, struct timespec end)
{
        return (double)(end.tv_sec - start.tv_sec) +
               (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}

static void print_block(const char *label, const word32 block[2])
{
        printf("%s: %08x %08x\n", label,
               (unsigned int)(block[0] & 0xffffffffU),
               (unsigned int)(block[1] & 0xffffffffU));
}

static void run_mode_samples(const word32 key[8])
{
        word32 iv[2] = { 0x0f1e2d3cUL, 0x4b5a6978UL };
        word32 plain[4] = { 0x11223344UL, 0x55667788UL,
                            0x99aabbccUL, 0xddeeff00UL };
        word32 ecb[2];
        word32 ofb_out[4];
        word32 cfb_cipher[4];
        word32 cfb_plain[4];
        word32 mac[2];
        gost_ctx ctx;

        gost_init(&ctx, key);

        gost_encrypt_block(&ctx, plain, ecb);

        word32 iv_ofb[2] = { iv[0], iv[1] };
        gostofb(plain, ofb_out, 2, iv_ofb, key);

        word32 iv_cfb[2] = { iv[0], iv[1] };
        gostcfbencrypt(plain, cfb_cipher, 2, iv_cfb, key);
        word32 iv_cfb_dec[2] = { iv[0], iv[1] };
        gostcfbdecrypt(cfb_cipher, cfb_plain, 2, iv_cfb_dec, key);

        gostmac(plain, 2, mac, key);

        printf("Mode samples (deterministic inputs)\n");
        print_block("  ECB sample      ", ecb);
        print_block("  OFB block 0     ", ofb_out);
        print_block("  OFB block 1     ", ofb_out + 2);
        print_block("  CFB cipher 0    ", cfb_cipher);
        print_block("  CFB cipher 1    ", cfb_cipher + 2);
        print_block("  CFB recovered 0 ", cfb_plain);
        print_block("  CFB recovered 1 ", cfb_plain + 2);
        print_block("  MAC             ", mac);
}

static void run_benchmark(size_t blocks_per_batch, size_t iterations,
                         const gost_ctx *ctx)
{
        word32 block[2];
        word32 *buffer = calloc(blocks_per_batch * 2, sizeof(word32));
        if (!buffer) {
                fprintf(stderr, "Failed to allocate buffer\n");
                exit(EXIT_FAILURE);
        }

        fill_buffer(buffer, blocks_per_batch);
        memcpy(block, buffer, sizeof(block));

        struct timespec start, end;
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
                perror("clock_gettime");
                free(buffer);
                exit(EXIT_FAILURE);
        }

        for (size_t iter = 0; iter < iterations; iter++) {
                for (size_t i = 0; i < blocks_per_batch; i++) {
                    gost_encrypt_block(ctx, &buffer[i * 2], block);
                    buffer[i * 2] = block[0];
                    buffer[i * 2 + 1] = block[1];
                }
        }

        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
                perror("clock_gettime");
                free(buffer);
                exit(EXIT_FAILURE);
        }

        size_t total_blocks = blocks_per_batch * iterations;
        double seconds = elapsed_seconds(start, end);
        double total_bytes = (double)total_blocks * sizeof(block);
        double mbps = (total_bytes / (1024.0 * 1024.0)) / seconds;

        printf("Benchmark complete.\n");
        printf("  Blocks processed : %zu\n", total_blocks);
        printf("  Total bytes      : %.2f MiB\n", total_bytes / (1024.0 * 1024.0));
        printf("  Elapsed time     : %.6f seconds\n", seconds);
        printf("  Throughput       : %.2f MiB/s\n", mbps);

        free(buffer);
}

static void usage(const char *prog)
{
        fprintf(stderr,
                "Usage: %s [blocks_per_batch] [iterations]\n"
                "  blocks_per_batch: number of 64-bit blocks processed per iteration (default 1024)\n"
                "  iterations      : number of iterations to run (default 1000)\n",
                prog);
}

int main(int argc, char **argv)
{
        size_t blocks_per_batch = 1024;
        size_t iterations = 1000;
        gost_ctx ctx;
        word32 key[8];

        if (argc >= 2)
                blocks_per_batch = (size_t)strtoul(argv[1], NULL, 0);
        if (argc >= 3)
                iterations = (size_t)strtoul(argv[2], NULL, 0);
        if (blocks_per_batch == 0 || iterations == 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        kboxinit();

        for (size_t i = 0; i < 8; i++)
                key[i] = (word32)(0x01020304UL * (i + 1));

        gost_init(&ctx, key);

        run_mode_samples(key);
        run_benchmark(blocks_per_batch, iterations, &ctx);
        return 0;
}
