#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>

#include "gost.h"

static uint64_t timespec_diff_ns(const struct timespec *start, const struct timespec *end)
{
    uint64_t s = (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000ull;
    uint64_t ns = (uint64_t)(end->tv_nsec - start->tv_nsec);
    return s + ns;
}

static double parse_cpu_mhz_line(const char *line)
{
    const char *match = strstr(line, "MHz");
    if (!match)
        return 0.0;

    /* Search backwards for ':' and parse the number after it */
    const char *colon = strchr(line, ':');
    if (!colon)
        return 0.0;

    errno = 0;
    double mhz = strtod(colon + 1, NULL);
    if (errno != 0)
        return 0.0;
    return mhz * 1e6; /* Hz */
}

static double detect_cpu_hz(void)
{
    /* Allow overriding from the environment for cross targets */
    const char *env = getenv("BENCH_CPU_HZ");
    if (env && *env) {
        errno = 0;
        double hz = strtod(env, NULL);
        if (errno == 0 && hz > 0)
            return hz;
    }

    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f)
        return 0.0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        double hz = parse_cpu_mhz_line(line);
        if (hz > 0) {
            fclose(f);
            return hz;
        }
    }

    fclose(f);
    return 0.0;
}

static void report_relative_rate(const char *label, double bytes_processed, double seconds, double cpu_hz)
{
    double bytes_per_sec = bytes_processed / seconds;
    printf("%-20s: processed %.2f MB/s", label, bytes_per_sec / (1024.0 * 1024.0));
    if (cpu_hz > 0.0) {
        double bytes_per_cycle = bytes_per_sec / cpu_hz;
        printf(" (%.3e bytes/cycle)", bytes_per_cycle);
    }
    putchar('\n');
}

static double run_single_block_bench(void (*fn)(const word32 *, word32 *, const word32 *),
                                     const char *label, size_t blocks, double cpu_hz)
{
    word32 key[8];
    word32 in[2];
    word32 out[2];
    struct timespec start, end;

    for (int i = 0; i < 8; i++)
        key[i] = 0x01010101u * (unsigned)(i + 1);
    in[0] = 0x11223344u;
    in[1] = 0x55667788u;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (size_t i = 0; i < blocks; i++)
        fn(in, out, key);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double seconds = (double)timespec_diff_ns(&start, &end) / 1e9;
    double mbps = (double)blocks * 8.0 / (seconds * 1e6); /* megabits per second */
    printf("%-20s: %zu blocks in %.3f s (%.2f Mb/s)\n", label, blocks, seconds, mbps);
    report_relative_rate(label, (double)blocks * 8.0, seconds, cpu_hz);
    return seconds;
}

static void run_neon_batch_bench(size_t blocks, double cpu_hz)
{
    word32 key[8];
    word32 *in = calloc(blocks * 2, sizeof(word32));
    word32 *out = calloc(blocks * 2, sizeof(word32));
    struct timespec start, end;

    if (!in || !out) {
        fprintf(stderr, "Allocation failed\n");
        free(in);
        free(out);
        return;
    }

    for (int i = 0; i < 8; i++)
        key[i] = 0x0F0E0D0Cu * (unsigned)(i + 1);
    for (size_t i = 0; i < blocks; i++) {
        in[2 * i] = (word32)(i ^ 0x55AA55AAu);
        in[2 * i + 1] = (word32)((i + 1) ^ 0xAA55AA55u);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    gostcrypt_neon_blocks((const word32(*)[2])in, (word32(*)[2])out, blocks, key);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double seconds = (double)timespec_diff_ns(&start, &end) / 1e9;
    double mbps = (double)blocks * 8.0 / (seconds * 1e6);
    printf("%-20s: %zu blocks in %.3f s (%.2f Mb/s)\n", "neon_batch", blocks, seconds, mbps);
    report_relative_rate("neon_batch", (double)blocks * 8.0, seconds, cpu_hz);

    free(in);
    free(out);
}

int main(int argc, char **argv)
{
    size_t blocks = 1 << 18; /* 256 Ki blocks by default */
    double cpu_hz;

    if (argc > 1)
        blocks = (size_t)strtoull(argv[1], NULL, 0);

    kboxinit();

    cpu_hz = detect_cpu_hz();
    if (cpu_hz > 0.0) {
        printf("Detected CPU frequency: %.3f MHz\n", cpu_hz / 1e6);
    } else {
        printf("CPU frequency not detected; set BENCH_CPU_HZ for per-cycle metrics.\n");
    }

    printf("Running %zu-block benchmarks...\n", blocks);
#if !defined(__ARM_NEON__)
    printf("(Host built without NEON; neon_batch reuses the scalar core for compatibility.)\n");
#endif
    run_single_block_bench(gostcrypt_reference, "reference_scalar", blocks, cpu_hz);
    run_single_block_bench(gostcrypt, "fast_scalar", blocks, cpu_hz);
    run_neon_batch_bench(blocks, cpu_hz);

    return 0;
}
