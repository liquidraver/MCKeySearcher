# MCKeySearcher

A high-performance Ed25519 public key searcher that finds keys matching specific hex prefixes. Built with custom AVX2-optimized Ed25519 implementation and Intel SHA Extensions for maximum speed.

This program was created to generate custom hexadecimal public key values for [MeshCore](https://github.com/meshcore-dev/MeshCore), allowing the app to display more visually appealing hex values.

## 🚀 TL;DR - Quick Start

```bash
# 1. Install dependencies and build
sudo apt update && sudo apt install build-essential git autotools-dev automake libtool pkg-config libssl-dev
git clone https://github.com/liquidraver/MCKeySearcher
cd MCKeySearcher
make

# 2. Generate a key (example: starting with "BEEF")
./mckeysearcher
# Enter: BEEF

# 3. IMPORTANT: Copy the private key from found_keys.txt to paper or insert into node
cat found_keys.txt

# 4. Securely delete the file (optional but recommended)
rm found_keys.txt
```

**⚠️ SECURITY:**
- Copy the private key to paper or insert directly into your node
- **NEVER** leave private keys on your computer
- Delete found_keys.txt after copying the key
- Private keys are automatically wiped from memory after use

## Features

- **Custom Ed25519 Implementation**: Built from scratch for maximum key generation performance
- **Intel SHA Extensions**: SHA-512 acceleration using Intel SHA-NI instructions (3-5x faster)
- **OpenSSL Fallback**: Fast SHA-512 when SHA-NI not available (2-3x faster than libsodium)
- **AVX2 SIMD Optimization**: Vectorized field arithmetic using Intel AVX2 instructions
- **High Performance**: Multi-threaded with CPU affinity, optimized for speed
- **Simple Interface**: Find keys with specific hex prefixes
- **Real-time Status**: Live progress updates and performance monitoring
- **Memory Security**: Private keys are securely wiped from memory immediately after use
- **Key Logging**: All found keys are logged to `found_keys.txt`

## Performance Optimizations

### SHA-512 Acceleration
The program automatically detects and uses the fastest available SHA-512 implementation:

1. **Intel SHA-NI** (Fastest): 3-5x faster than libsodium on supported CPUs
2. **OpenSSL** (Fast): 2-3x faster than libsodium when SHA-NI not available
3. **libsodium** (Secure): Cryptographic fallback for maximum compatibility

### AVX2 SIMD
- Custom Ed25519 field arithmetic using Intel AVX2 instructions
- Optimized for 12th Gen Intel processors and newer
- Vectorized operations for parallel processing

## Prerequisites

This program requires a Linux system with AVX2 support and the following packages:

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential git autotools-dev automake libtool pkg-config libssl-dev
```

### CentOS/RHEL/Fedora
```bash
sudo yum groupinstall "Development Tools"
sudo yum install git autoconf automake libtool pkgconfig openssl-devel
# OR for newer versions:
sudo dnf groupinstall "Development Tools"
sudo dnf install git autoconf automake libtool pkgconfig openssl-devel
```

### Arch Linux
```bash
sudo pacman -S base-devel git autoconf automake libtool pkgconf openssl
```

**Note**: The program automatically downloads and builds libsodium from source during the build process. OpenSSL is used for SHA-512 acceleration when Intel SHA-NI is not available.

## Installation and Usage

### Step 1: Clone the Repository
```bash
git clone https://github.com/liquidraver/MCKeySearcher
cd MCKeySearcher
```

### Step 2: Build the Program

#### Simple Build (Recommended for most users)
```bash
make
```

#### Profile-Guided Optimization Build (For maximum performance)
```bash
# First, generate profiling data
make pgo-generate

# Run the program to collect profiling data
# ⚠️  IMPORTANT: Do NOT use Ctrl+C to exit during profiling!
# The program must exit normally to write profiling data.

# Automated profiling (recommended)
echo -e "123456\n" | ./mckeysearcher

# After collecting data, rebuild with optimizations
make pgo-use

# Now run the optimized version
./mckeysearcher
```

**⚠️  PGO Profiling Requirements:**
- **Never use Ctrl+C** to exit during profiling - this prevents profiling data from being written
- The program must exit naturally by finding a key
- Profiling data files (`.gcda`, `.gcno`) will be created in the current directory

### Step 3: Run the Program

```bash
./mckeysearcher
```

## Usage Examples

### Example 1: Find a key starting with "BEEF"
```bash
$ ./mckeysearcher
Enter the prefix bytes from 0123456789ABCDEF (e.g. BEEFF00D, 23DF, 43): BEEF
```

The program will:
1. Ask for a hex prefix pattern
2. Search for Ed25519 keys matching that pattern
3. Display found keys in real-time
4. Save all found keys to `found_keys.txt`
5. Continue searching until interrupted

## Output

- **Console**: Real-time status updates showing attempts, matches found, and keys per second
- **Log File**: All found keys are saved to `found_keys.txt` in the current directory
- **Format**: Complete key information including pattern, public key, private key, seed, thread, attempts, and timestamp
- **Memory Security**: Private keys are automatically wiped from memory immediately after logging to file

## Performance Features

1. **Custom Ed25519 Implementation**: Built specifically for key generation, not signing/verification
2. **AVX2 SIMD Operations**: Vectorized field arithmetic for maximum CPU utilization
3. **Multi-threading**: Uses all available CPU cores minus one for the OS
4. **CPU Affinity**: Threads are pinned to specific CPU cores to reduce overhead
5. **Profile-Guided Optimization**: Optional PGO build for maximum performance tuning

## Hardware Requirements

- **CPU**: Intel/AMD processor with AVX2 support (Intel Haswell+ or AMD Excavator+)
- **Memory**: At least 4GB RAM recommended
- **OS**: Linux (Ubuntu, Debian, CentOS, etc.)

## Security Warning

⚠️ **IMPORTANT**: This program generates cryptographically secure Ed25519 private keys using libsodium's secure random number generator. However, generating keys on your computer, storing them in files, copying them, or doing anything with private keys on a general-purpose computer is NEVER secure.

### Security Features

✅ **Memory Security**: Private keys are automatically and securely wiped from memory immediately after use
- Memory is overwritten with cryptographically secure random data before zeros
- Wiping happens immediately after logging to file

### Best Practices

1. **Immediate Transfer**: Copy the private key from `found_keys.txt` to paper or insert directly into your node
2. **Never Store**: Don't leave private keys on your computer longer than necessary
3. **Memory Protection**: Private keys are automatically wiped from memory, but avoid running other programs while keys are in memory

### The Most Secure Approach

The most secure way is to let the node generate keys on itself after a full wipe and never save or display the keys anywhere else.

**You need to import the PRIVATE key from found_keys.txt to make the app display the custom public key!**

## Troubleshooting

### PGO (Profile-Guided Optimization) Issues

**Problem**: `warning: 'mckeysearcher-main.gcda' profile count data file not found`

**Solution**: This means the profiling data wasn't generated properly. Follow these steps:

1. **Ensure you built the instrumented version:**
   ```bash
   make pgo-generate
   ```

2. **Run the instrumented version properly:**
   - **DO NOT use Ctrl+C** to exit
   - Let the program exit naturally by finding a key
   - Use a longer prefix (like "12345678") for more profiling data
   
   **Recommended automated approach:**
   ```bash
   echo -e "1234\n" | ./mckeysearcher
   ```

3. **Verify profiling files were created:**
   ```bash
   ls -la *.gcda *.gcno
   ```

4. **If files exist, build the optimized version:**
   ```bash
   make pgo-use
   ```

**Common PGO Mistakes:**
- Using Ctrl+C to exit during profiling
- Running the program for too short a time
- Not letting the program exit naturally

**Alternative**: If PGO continues to cause issues, use the simple build:
```bash
make clean
make
```

### Build Issues

**Problem**: `make` fails with dependency errors

**Solution**: 
1. **Clean and rebuild:**
   ```bash
   make clean
   make
   ```

2. **Check dependencies:**
   ```bash
   sudo apt update
   sudo apt install build-essential git autotools-dev automake libtool pkg-config
   ```

3. **Manual libsodium build:**
   ```bash
   cd deps/libsodium
   ./autogen.sh
   ./configure --enable-static --disable-shared
   make
   cd ../..
   make
   ```

## Performance Tips

1. **Use Profile-Guided Optimization**: For maximum performance, use the PGO build process
2. **Reserve Cores**: The program automatically reserves one core for the OS
3. **AVX2 Support**: Ensure your CPU supports AVX2 instructions for maximum performance
4. **CPU Affinity**: Threads are automatically pinned to specific CPU cores

## Technical Details

### Ed25519 Implementation

The program uses a custom, highly optimized Ed25519 implementation:

- **Field Arithmetic**: Custom 256-bit field operations optimized for AVX2
- **Point Operations**: Efficient point doubling and addition using extended coordinates
- **Scalar Multiplication**: Double-and-add algorithm optimized for key generation
- **No Signing/Verification**: Focused solely on key generation for maximum speed

### AVX2 Optimizations

- **Vectorized Field Operations**: Addition, subtraction, multiplication using `_mm256_*` intrinsics
- **Aligned Memory**: 32-byte aligned buffers for optimal SIMD performance
- **Batch Processing**: Processes multiple keys simultaneously for better cache utilization

### Threading Model

- **Worker Threads**: One thread per CPU core (minus one for OS)
- **CPU Affinity**: Threads are pinned to specific cores to reduce context switching
- **Lock-free Counters**: Atomic operations for thread-safe performance monitoring
