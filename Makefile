CC ?= gcc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -pedantic
NEON_FLAGS ?=

SRC = gost.c
HDR = gost.h

.PHONY: all clean test bench

all: test bench

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) $(NEON_FLAGS) -c $< -o $@

test: tests.o gost.o
	$(CC) $(CFLAGS) $(NEON_FLAGS) $^ -o $@

bench: bench.o gost.o
	$(CC) $(CFLAGS) $(NEON_FLAGS) $^ -o $@

clean:
	rm -f *.o test bench
