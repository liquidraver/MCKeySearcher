# MCKeySearcher - CPU-Only Ed25519 Key Searcher

A high-performance Ed25519 key searcher optimized for CPU-only operation using libsodium's cryptographically secure implementations.

## Features

- CPU-only implementation using libsodium's secure random number generation
- NUMA-aware memory allocation and thread affinity
- Multiple search modes: prefix only, suffix only, or prefix+suffix
- SIMD-optimized prefix/suffix checking with AVX2 support
- Real-time performance monitoring and entropy quality analysis

## Requirements

- Ubuntu 24.04/22.04 or Windows 10/11 with WSL2
- 64-bit system with AVX2 support
- Modern CPU with multiple cores (8+ cores recommended)

## Installation

### Ubuntu/Linux

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential g++ make
sudo apt install -y libsodium-dev libnuma-dev
```

### Windows (WSL2)

1. Install WSL2 with Ubuntu
2. Follow Ubuntu installation steps above
3. Verify installation: `pkg-config --cflags --libs libsodium`

## Building

```bash
make
```

### Build Options

```bash
make debug          # Debug build
make pgo            # Profile-guided optimization
make clean          # Clean build files
make install-deps   # Install dependencies
```

## Usage

```bash
./mckeysearcher
```

### Program Flow

1. Enter hex prefix (e.g., BEEF, 1234)
2. Choose search mode:
   - 1: Prefix only
   - 2: Suffix only
   - 3: Prefix + Suffix
3. Enter suffix (if mode 2 or 3 selected)
4. Choose search behavior:
   - 1: Find one key
   - 2: Find N keys
   - 3: Continuous search
5. Monitor progress and results
6. Found keys saved to `found_keys.txt`

## Performance

- Expected: 800k-1.2M keys/sec on modern CPUs
- Optimized for AVX2, multiple cores, and large L3 cache
- Batch size automatically adjusts based on system capabilities

## Configuration

### CPU Threads
- Automatically detects available cores
- Reserves one core for OS by default

### Batch Sizes
- Adaptive based on L3 cache size
- Range: 32,768 to 262,144 keys per batch

### NUMA Settings
- Automatically detects NUMA nodes
- Allocates memory on appropriate nodes
- Sets thread affinity to specific CPU cores

## Architecture

### CPU Workers
- Multi-threaded with NUMA awareness
- Generates complete Ed25519 keys using libsodium
- Optimized batch processing with prefetching
- SIMD-optimized prefix/suffix checking

### Cryptographic Implementation
- Ed25519: libsodium's optimized implementation
- Random Generation: libsodium's `randombytes_buf()`
- Key Format: 64-byte private keys, 32-byte public keys

### Memory Management
- NUMA-aware allocation
- Batch processing with large batches
- Cache optimization with prefetching and alignment
