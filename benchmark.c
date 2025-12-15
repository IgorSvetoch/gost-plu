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

static void run_benchmark(size_t blocks_per_batch, size_t iterations)
{
        word32 key[8];
        word32 block[2];
        word32 *buffer = calloc(blocks_per_batch * 2, sizeof(word32));
        if (!buffer) {
                fprintf(stderr, "Failed to allocate buffer\n");
                exit(EXIT_FAILURE);
        }

        /* Deterministic key and initial block contents. */
        for (size_t i = 0; i < 8; i++)
                key[i] = (word32)(0x01020304UL * (i + 1));

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
                    gostcrypt(&buffer[i * 2], block, key);
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

        if (argc >= 2)
                blocks_per_batch = (size_t)strtoul(argv[1], NULL, 0);
        if (argc >= 3)
                iterations = (size_t)strtoul(argv[2], NULL, 0);
        if (blocks_per_batch == 0 || iterations == 0) {
                usage(argv[0]);
                return EXIT_FAILURE;
        }

        kboxinit();
        run_benchmark(blocks_per_batch, iterations);
        return 0;
}
