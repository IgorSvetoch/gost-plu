CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
LANGFLAGS ?= -x c
LDFLAGS ?=
LDLIBS ?=

SOURCES = GOST.C benchmark.c
target = gost_benchmark

all: $(target)

$(target): $(SOURCES) gost.h
	$(CC) $(CFLAGS) $(LANGFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(LDLIBS)

format:
	@echo "No automatic formatter configured."

test: all
	./$(target) 1000 10

clean:
	rm -f $(target) *.o

# Build optimized for Cortex-A9 with NEON enabled
cortex-a9-neon: CFLAGS += -mcpu=cortex-a9 -mfpu=neon -mfloat-abi=hard
cortex-a9-neon: $(target)

.PHONY: all clean format test cortex-a9-neon
