# MCKeySearcher build system.
#
# Default target: Cascade Lake (Xeon Gold 5xxx, Xeon Platinum 8xxx, and any newer
# AVX-512 server CPU). Override the architecture via:
#
#   make MARCH=native              # build for the CPU you're on
#   make MARCH=skylake-avx512      # older AVX-512 Xeon
#   make MARCH=znver4              # AMD Zen 4
#   make MARCH=x86-64-v3           # generic AVX2 (broadest compatibility)
#
# WARNING: the vendored vendor/libsodium/libsodium.a is built for Cascade Lake
# and uses AVX-512. If your CPU lacks AVX-512, rebuild libsodium first — see
# the "Rebuilding libsodium for your hardware" section of the README.
#
# PGO (Profile-Guided Optimization) workflow for ~5-20% extra throughput:
#
#   1. make pgo-generate
#   2. MCKS_THREADS=1 bash -c 'printf "DEA\n1\n2\n30\n" | ./mckeysearcher_pgo'
#   3. make pgo-use
#
# Use MCKS_THREADS=1 during step 2 — multi-threaded PGO training is dominated
# by cache-line contention on shared profile counters.

MARCH ?= cascadelake
CXX   ?= g++
CC    ?= gcc

SODIUM_DIR = vendor/libsodium

CXX_FLAGS = -std=c++17 -O3 -march=$(MARCH) -mtune=$(MARCH) \
            -fomit-frame-pointer -pthread -DNDEBUG \
            -funroll-loops -fprefetch-loop-arrays \
            -flto -fwhole-program -fuse-linker-plugin \
            -fstack-protector-strong -fno-asynchronous-unwind-tables \
            -fno-unwind-tables -fno-ident \
            -mavx2 -mfma -mbmi2 -mpopcnt -mlzcnt \
            -mprefer-vector-width=256 \
            -ffast-math -fno-trapping-math -fno-math-errno \
            -fno-signed-zeros -fno-rounding-math -fno-signaling-nans \
            -I$(SODIUM_DIR)/include

# Extra flags injected by PGO targets (-fprofile-generate / -fprofile-use).
EXTRA_CFLAGS ?=

LIBS = $(SODIUM_DIR)/libsodium.a -lpthread

CPP_SRC = main.cpp
TARGET ?= mckeysearcher

all: $(TARGET)

$(TARGET): $(CPP_SRC) $(SODIUM_DIR)/libsodium.a
	$(CXX) $(CXX_FLAGS) $(EXTRA_CFLAGS) -static-libstdc++ -static-libgcc \
	    $(CPP_SRC) $(LIBS) -o $(TARGET)

# PGO step 1: build instrumented binary that writes profile data to ./pgo/
pgo-generate:
	mkdir -p pgo
	$(MAKE) clean-binary
	$(MAKE) EXTRA_CFLAGS="-fprofile-generate=$(CURDIR)/pgo" TARGET=mckeysearcher_pgo

# PGO step 3: rebuild using profile data collected by the instrumented binary
pgo-use:
	@if [ ! -d pgo ] || [ -z "$$(ls -A pgo 2>/dev/null)" ]; then \
	    echo "Error: no profile data in ./pgo/. Run 'make pgo-generate' and the instrumented binary first."; \
	    exit 1; \
	fi
	$(MAKE) clean-binary
	$(MAKE) EXTRA_CFLAGS="-fprofile-use=$(CURDIR)/pgo -fprofile-correction"

clean-binary:
	rm -f mckeysearcher mckeysearcher_pgo

clean:
	rm -f mckeysearcher mckeysearcher_pgo *.o *.gcda *.gcno *.profraw
	rm -rf pgo

install-deps:
	sudo apt update
	sudo apt install -y build-essential g++ make

.PHONY: all clean clean-binary pgo-generate pgo-use install-deps
