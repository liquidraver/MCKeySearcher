# MCKeySearcher

A high-performance Ed25519 public key searcher that finds keys matching specific hex prefixes and/or suffixes.

This program was created ~~to save humanity from the effects of global wa~~ generate custom hexadecimal public key values for [MeshCore](https://github.com/meshcore-dev/MeshCore), allowing the app to display more visually appealing hex values.
If parts of the code seem as though they were influenced by AI, that's no coincidence. ;)

## 🚀 TL;DR - Quick Start for Simple Users

**For users who just want to generate a key and use it immediately:**

```bash
# 1. Install dependencies and build
sudo apt update && sudo apt install build-essential git autotools-dev automake libtool pkg-config
git clone https://github.com/liquidraver/MCKeySearcher
cd MCKeySearcher
make

# 2. Generate a key (example: starting with "BEEF")
./findkey
# Enter: BEEF
# Choose: 1 (Prefix only)
# Choose: 1 (Find one key and exit)

# 3. IMPORTANT: Copy the private key from found_keys.txt to paper or insert into node
cat found_keys.txt

# 4. Securely wipe the file (optional but recommended)
./findkey --wipe
```

**⚠️ SECURITY:**
- Copy the private key to paper or insert directly into your node
- **NEVER** leave private keys on your computer
- Use `./findkey --wipe` to securely delete found_keys.txt
- Private keys are automatically wiped from memory after use

## Features

- **Cryptographically Secure**: Uses libsodium's secure random number generator and Ed25519 implementation
- **High Performance**: Multi-threaded with CPU affinity, optimized for speed
- **Flexible Search**: Find keys with specific hex prefixes, suffixes, or both
- **Real-time Status**: Live progress updates and performance monitoring
- **Three Modes**: Find one key, find n keys and exit, or run continuously
- **Key Logging**: All found keys are logged to `found_keys.txt`
- **Memory Security**: Private keys are securely wiped from memory immediately after use
- **Secure File Wiping**: Built-in secure deletion of found_keys.txt

## Prerequisites

This program requires a Linux system with the following packages for building dependencies from source:

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential git autotools-dev automake libtool pkg-config
```

### CentOS/RHEL/Fedora
```bash
sudo yum groupinstall "Development Tools"
sudo yum install git autoconf automake libtool pkgconfig
# OR for newer versions:
sudo dnf groupinstall "Development Tools"
sudo dnf install git autoconf automake libtool pkgconfig
```

### Arch Linux
```bash
sudo pacman -S base-devel git autoconf automake libtool pkgconf
```

**Note**: The program automatically downloads and builds libsodium and ed25519 from source during the build process, so no additional cryptographic libraries need to be installed separately.

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

# Method 1: Automated profiling (recommended)
echo -e "123456\n1\n1" | ./findkey

# Method 2: Manual profiling
# ./findkey
# When prompted:
# 1. Enter a test prefix (e.g., "123456" for longer runtime)
# 2. Choose search mode (1 or 2)
# 3. Choose "Find one key and exit" (option 1) for controlled exit
# 4. Let the program find a key and exit naturally
# 5. OR choose "Run continuously" and let it run for 10-30 minutes, then choose option 1 in search behavior

# After collecting data, rebuild with optimizations
make pgo-use

# Now run the optimized version
./findkey
```

**⚠️  PGO Profiling Requirements:**
- **Never use Ctrl+C** to exit during profiling - this prevents profiling data from being written
- The program must exit normally (either by finding a key or choosing "Find one key and exit")
- Profiling data files (`.gcda`, `.gcno`) will be created in the current directory
- If no profiling files are created, the PGO optimization will not work

### Step 3: Run the Program
```bash
./findkey
```

## Usage Examples

### Example 1: Find a key starting with "BEEF"
```bash
$ ./findkey
Enter the prefix/suffix bytes from 0123456789ABCDEF (e.g. BEEFF00D, 23DF, 43): BEEF
Search mode:
1. Prefix only (Default)
2. Prefix & Prefix + Suffix
Enter your choice (1 or 2): 1

Search behavior:
1. Find one key and exit
2. Run continuously (find all keys)
Enter your choice (1 or 2): 1
```

### Example 2: Find a key starting AND ending with "1234"
```bash
$ ./findkey
Enter the prefix/suffix bytes from 0123456789ABCDEF (e.g. BEEFF00D, 23DF, 43): 1234
Search mode:
1. Prefix only (Default)
2. Prefix & Prefix + Suffix
Enter your choice (1 or 2): 2

Search behavior:
1. Find one key and exit
2. Run continuously (find all keys)
Enter your choice (1 or 2): 1
```

### Example 3: Securely wipe found_keys.txt after use
```bash
# After copying your private key to paper or inserting into node
./findkey --wipe

# Or use the short form
./findkey -w
```

### Example 4: Get help
```bash
./findkey --help
```

## Program Options

### Search Modes
1. **Prefix only**: Find keys where the public key hex starts with your specified pattern
2. **Prefix & Prefix + Suffix**: Find keys where the public key hex starts AND ends with your specified pattern

### Search Behavior
1. **Find one key and exit**: Stop after finding the first matching key
2. **Enter a number how many keys to find**: Stop after finding the specified number of keys (approximate with few characters)
3. **Run continuously**: Continue searching and find all matching keys (may create large log files for short prefixes)

### Command Line Options
- `--wipe`, `-w`, `--secure-wipe`: Securely wipe found_keys.txt file (overwrites with random data before deletion)
- `--help`, `-h`: Show help message

## Output

- **Console**: Real-time status updates showing attempts, matches found, and keys per second
- **Log File**: All found keys are saved to `found_keys.txt` in the current directory
- **Format**: `Label: PrivateKey | PublicKey`
- **Memory Security**: Private keys are automatically wiped from memory immediately after logging to file
- **Exit Message**: Confirmation that all private key data has been securely wiped from memory

## Performance Tips

1. **Use Profile-Guided Optimization**: For maximum performance, use the PGO build process
2. **Reserve Cores**: The program automatically reserves one core for the OS
3. **Batch Processing**: Uses optimized batch processing for better cache utilization
4. **CPU Affinity**: Threads are pinned to specific CPU cores to reduce overhead

## Security Warning

⚠️ **IMPORTANT**: This program generates cryptographically secure Ed25519 private keys using libsodium's secure random number generator. However, generating keys on your computer, storing them in files, copying them, or doing anything with private keys on a general-purpose computer is NEVER secure.

### Security Features

✅ **Memory Security**: Private keys are automatically and securely wiped from memory immediately after use
- Memory is overwritten with cryptographically secure random data before zeros
- Wiping happens immediately after logging to file
- All private key data is cleared from batch arrays after processing

✅ **Secure File Wiping**: Built-in secure deletion of found_keys.txt
- Overwrites file with random data multiple times before deletion
- Use `./findkey --wipe` to securely delete the file
- Prevents recovery even with advanced forensic tools

### Best Practices

1. **Immediate Transfer**: Copy the private key from `found_keys.txt` to paper or insert directly into your node
2. **Never Store**: Don't leave private keys on your computer longer than necessary
3. **Secure Wipe**: Use `./findkey --wipe` after copying the key
4. **Memory Protection**: Private keys are automatically wiped from memory, but avoid running other programs while keys are in memory

### The Most Secure Approach

The most secure way is to let the node generate keys on itself after a full wipe and never save or display the keys anywhere else.

**You need to import the PRIVATE key from found_keys.txt to make the app display the custom public key!**

## Troubleshooting

### PGO (Profile-Guided Optimization) Issues

**Problem**: `warning: 'findkey-main.gcda' profile count data file not found`

**Solution**: This means the profiling data wasn't generated properly. Follow these steps:

1. **Ensure you built the instrumented version:**
   ```bash
   make pgo-generate
   ```

2. **Run the instrumented version properly:**
   - **DO NOT use Ctrl+C** to exit
   - Let the program exit naturally by finding a key or choosing "Find one key and exit"
   - Use a longer prefix (like "12345678") for more profiling data
   
   **Recommended automated approach:**
   ```bash
   echo -e "1234\n1\n1" | ./findkey
   ```
   This automatically provides:
   - Prefix: "1234" (4 characters - quick but sufficient for profiling)
   - Search mode: 1 (Prefix only)
   - Search behavior: 1 (Find one key and exit)

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
- Using the wrong executable (must use the one built with `pgo-generate`)

**Alternative**: If PGO continues to cause issues, use the simple build:
```bash
make clean
make
```

### Secure Wipe Issues

**Problem**: `./findkey --wipe` fails or doesn't work as expected

**Solution**: 
1. **Check if file exists**: The wipe command will tell you if `found_keys.txt` doesn't exist
2. **Permission issues**: Make sure you have write permissions in the current directory
3. **File in use**: Close any programs that might have the file open
4. **Manual wipe**: If the built-in wipe fails, you can manually delete the file:
   ```bash
   rm found_keys.txt
   ```
   (Note: Manual deletion is less secure than the built-in wipe)

**Note**: The secure wipe feature overwrites the file with random data multiple times before deletion, making it impossible to recover the private keys even with advanced forensic tools.
