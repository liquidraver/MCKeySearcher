# MCKeySearcher — High-Performance Ed25519 Vanity Key Searcher

Multi-threaded Ed25519 keypair generator that searches for public keys matching a given hex prefix, suffix, or both. Built for MeshCore-format keys; the seeds it produces are standard RFC 8032 Ed25519 seeds usable with any compliant implementation (libsodium, PyNaCl, OpenSSL, etc.).

## What's in this build

- **Vendored libsodium 1.0.22**, statically linked. No `libsodium-dev` runtime dependency.
- **PGO-tuned for Cascade Lake** out of the box — the vendored `libsodium.a` was built with profile data from a real key-search workload on Xeon Gold 5220.
- **Per-thread CSPRNG**: each worker draws one 32-byte master from `/dev/urandom` (via libsodium) at startup, then derives per-iteration seeds via `SHA-512(master ‖ counter)`. Cryptographically equivalent to fresh kernel entropy per attempt, without per-iteration syscalls or mutex contention.
- **Standard 32-byte Ed25519 seeds saved with every found key**, so you can regenerate the keypair in any other Ed25519 library.
- **Each found keypair is verified** by re-deriving the public key from the private scalar before logging.
- **Sensitive memory is zeroed at thread exit** via `sodium_memzero`.
- **Cascade Lake / AVX-512 / VNNI / AES-NI / SHA-NI feature detection** at startup.

## Throughput reference

On a 2-socket Intel Xeon Gold 5220 (72 cores, Cascade Lake) running this build: **~1.75 M keys/sec**.

| Pattern                | Bits | Expected time @ 1.75 M/s |
|------------------------|------|--------------------------|
| 4-char prefix          | 16   | ~0.04 sec                |
| 6-char prefix          | 24   | ~10 sec                  |
| 8-char prefix          | 32   | ~41 min                  |
| 10-char prefix         | 40   | ~7 days                  |
| 12-char prefix         | 48   | ~5 years                 |
| 8-char prefix + 8-char suffix | 64 | ~332,000 years        |

## Requirements

- Linux x86-64 (Ubuntu 24.04 LTS or compatible). Windows: WSL2 with Ubuntu.
- AVX2-capable CPU minimum. AVX-512 strongly recommended.
- GCC 13.3+ (GCC 14+ recommended for best AVX-512 codegen).

## Quick build

```bash
sudo apt update && sudo apt install -y build-essential g++ make
make
./mckeysearcher
```

This produces a binary tuned for Cascade Lake, which runs on any Cascade Lake / Ice Lake / Sapphire Rapids server CPU.

If you're on a different CPU family, see [Building for your hardware](#building-for-your-hardware).

## Usage

```
./mckeysearcher
```

Interactive prompts:
1. **Hex prefix** (e.g. `BEEF`, `DEADBEEF`)
2. **Search mode** — `1` prefix only, `2` suffix only, `3` prefix + suffix
3. **Hex suffix** — only if mode 2 or 3, must be even-length (whole bytes)
4. **Behavior** — `1` stop on first match, `2` stop after N matches, `3` continuous

Found keys are appended to `found_keys.txt`:

```
CPU-Prefix: <128-hex-priv> | <64-hex-pub> | SEED: <64-hex-seed> | RFC_8032_COMPLIANT
```

The 32-byte SEED regenerates the keypair via the standard Ed25519 derivation (`SHA-512(seed)` → clamp → scalarmult). It works with any Ed25519 implementation.

### Environment overrides

- `MCKS_THREADS=N` — override worker thread count (default: all cores). Used during PGO training to avoid profile-counter cache-line contention.

## Building for your hardware

The default `make` produces a **Cascade Lake** binary. To build for the CPU you're sitting at:

```bash
make clean
make MARCH=native
```

Other useful values for `MARCH`:

| `MARCH=`           | For                                      |
|--------------------|------------------------------------------|
| `native`           | The CPU you're compiling on              |
| `cascadelake`      | Xeon Gold 5xxx, Xeon Platinum 8xxx (default) |
| `skylake-avx512`   | Older AVX-512 Xeon (Skylake-SP)          |
| `icelake-server`   | Ice Lake Xeon (3rd-gen Xeon Scalable)    |
| `sapphirerapids`   | Sapphire Rapids (4th-gen Xeon Scalable)  |
| `znver3`, `znver4` | AMD EPYC Zen 3 / Zen 4                   |
| `x86-64-v3`        | Generic AVX2 (Haswell+, broadest compat) |

> ⚠️ **The vendored `vendor/libsodium/libsodium.a` is built for Cascade Lake and contains AVX-512 instructions.** If your CPU lacks AVX-512 (most consumer Intel CPUs since 12th gen, AMD pre-Zen 4, etc.), the binary will crash with `Illegal instruction` even when built with `MARCH=native`. Rebuild libsodium first — see the next section.

## Rebuilding libsodium for your hardware

The shipped `vendor/libsodium/libsodium.a` is Cascade Lake + PGO-tuned for a specific Xeon Gold 5220 vanity-search workload. To rebuild it for your CPU:

```bash
# 1. Clone libsodium next to this repo
cd ..
git clone https://github.com/jedisct1/libsodium libsodium
cd libsodium
git checkout 1.0.22-RELEASE  # or any later stable tag
./autogen.sh -s

# 2. Build for your CPU. Replace MARCH below.
MARCH=native  # or whatever you'd pass to make MARCH=...
./configure --prefix=$(pwd)/_install --disable-shared --enable-static \
    CFLAGS="-O3 -march=$MARCH -mtune=$MARCH -fomit-frame-pointer -fPIC"
make -j$(nproc) && make install

# 3. Replace the vendored copy and rebuild MCKeySearcher
cd ../MCKeySearcher
rm -rf vendor/libsodium
mkdir -p vendor/libsodium
cp -r ../libsodium/_install/include vendor/libsodium/
cp ../libsodium/_install/lib/libsodium.a vendor/libsodium/
make clean && make MARCH=$MARCH
```

This gives you a libsodium with the Curve25519 scalarmult ASM and SHA-512 C code regenerated for your specific microarchitecture. Expect 0–30% improvement vs the default vendored `.a`, depending on how different your CPU is from Cascade Lake.

## Maximum throughput (PGO)

Profile-Guided Optimization rebuilds the binary using runtime measurements of which branches are hot. Expected gain on top of `-O3`: **~5–20%**.

There are two PGO passes you can do — `mckeysearcher` itself, and the underlying libsodium. Doing both gets you the biggest win.

### Step 1 — install GCC 14 (recommended)

GCC 14 has noticeably better AVX-512 codegen and smarter LTO than GCC 13:

```bash
sudo apt install -y g++-14 gcc-14
export CXX=g++-14 CC=gcc-14
```

### Step 2 — PGO the searcher

```bash
# Build instrumented binary
make pgo-generate

# Run a profile-collection workload. MCKS_THREADS=1 is critical: with 72
# threads, profile-counter cache-line contention can make this 200x slower.
MCKS_THREADS=1 bash -c 'printf "DEA\n1\n2\n30\n" | ./mckeysearcher_pgo'

# Rebuild using the collected profile data
make pgo-use

# Test
echo -e "DEADBEEFDEADBEEF\n1\n1" | timeout 30 ./mckeysearcher
```

### Step 3 — PGO libsodium too (optional, bigger gain)

Most of your CPU time is in libsodium's scalarmult and SHA-512. Rebuilding libsodium with profile data from your actual workload typically beats step 2 alone.

```bash
cd ../libsodium

# Phase 1: instrumented libsodium
./configure --prefix=$(pwd)/_install --disable-shared --enable-static \
    CFLAGS="-O3 -march=$MARCH -mtune=$MARCH -fomit-frame-pointer -fPIC -fprofile-generate" \
    LDFLAGS="-fprofile-generate"
make clean && make -j$(nproc) && make install

# Vendor it, build instrumented searcher, run training
cd ../MCKeySearcher
cp ../libsodium/_install/lib/libsodium.a vendor/libsodium/
make clean && make pgo-generate
MCKS_THREADS=1 bash -c 'printf "DEA\n1\n2\n30\n" | ./mckeysearcher_pgo'

# Phase 2: rebuild libsodium with profile data
cd ../libsodium
./configure --prefix=$(pwd)/_install --disable-shared --enable-static \
    CFLAGS="-O3 -march=$MARCH -mtune=$MARCH -fomit-frame-pointer -fPIC -fprofile-use -fprofile-correction" \
    LDFLAGS="-fprofile-use -fprofile-correction"
make clean && make -j$(nproc) && make install

# Vendor the optimized libsodium and rebuild searcher with PGO
cd ../MCKeySearcher
cp ../libsodium/_install/lib/libsodium.a vendor/libsodium/
make pgo-use
```

`warning: profile count data file not found` messages during the libsodium PGO use phase are normal — they're for code paths (BLAKE2, AES-GCM, HMAC, etc.) that the vanity-search workload doesn't exercise. Only files in the actual hot path (Curve25519 scalarmult, SHA-512 implementation) get PGO benefit, which is what we want.

## Security

- Per-thread 32-byte master is drawn from the kernel CSPRNG via libsodium's `randombytes_buf` (which uses `getrandom(2)` on Linux).
- Per-iteration seed = `SHA-512(master ‖ counter)[0..32]`. With a 256-bit unknown master, this is a strong PRF — cryptographically equivalent to fresh kernel entropy per attempt.
- Per-iteration expanded private key = `SHA-512(seed)`, clamped per RFC 8032. The public key is then derived via `crypto_scalarmult_ed25519_base_noclamp`.
- Each found keypair is **verified** before logging by re-deriving the public key from the private scalar and comparing.
- Stack buffers holding sensitive material (`master`, `prf_input`, `seed`, `sha512_digest`, `privkey`) are zeroed at thread exit via `sodium_memzero`.
- Built with `-fstack-protector-strong` for stack-canary protection.

## Architecture

- One worker thread per core, pinned to a specific CPU via `pthread_setaffinity_np` for cache locality and balanced NUMA placement.
- Hot loop is purely per-thread: `SHA-512(master ‖ counter) → SHA-512(seed) → scalarmult → memcmp`. No locks, no atomics in the inner loop.
- The match check uses pre-decoded byte arrays + `memcmp` (the prefix/suffix hex strings are parsed once at startup, not per attempt).
- Atomics (`total_attempts`, `keys_found`, `stop_search`) are touched only every 4096 iterations or on the cold match path.

## License

See LICENSE (or original repo upstream).
