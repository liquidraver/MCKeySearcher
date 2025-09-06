# MCKeySearcher - Hybrid CPU+GPU Ed25519 Key Searcher

A high-performance Ed25519 key searcher that combines CPU and GPU acceleration for maximum performance. Optimized for server environments with NUMA support and AVX-512 optimizations.

## Features

- **Hybrid CPU+GPU**: GPU accelerates random generation, CPU computes Ed25519 keys
- **Server Optimized**: NUMA-aware memory allocation and thread affinity
- **Multiple Search Modes**: Prefix only, suffix only, or prefix+suffix
- **High Performance**: Achieves ~1.5M keys/sec with 2M+ spikes on optimized systems
- **Cryptographically Secure**: Uses libsodium's proven Ed25519 implementation
- **NUMA Support**: Optimized for multi-socket systems

## Requirements

- Ubuntu 24.04/22.04 (recommended) or Windows 10/11 with WSL2
- CUDA-capable GPU (GTX 1080 or better recommended)
- CUDA toolkit 11.0 or later (12.5+ recommended)
- 64-bit system with AVX-512 support (for maximum performance)

## Installation

### Ubuntu/Linux Installation

### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Build Tools
```bash
sudo apt install -y build-essential g++ make
```

### Step 3: Install CUDA Toolkit
```bash
# Method 1: Install via NVIDIA repository (recommended)
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt update
sudo apt install -y cuda-toolkit-12-5

# Method 2: Alternative - Install via conda (if you prefer)
# conda install -c nvidia cuda-toolkit
```

### Step 4: Install Dependencies
```bash
sudo apt install -y libsodium-dev libnuma-dev
```

### Step 5: Set Environment Variables
```bash
echo 'export PATH=/usr/local/cuda-12.5/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-12.5/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

### Step 6: Verify CUDA Installation
```bash
nvcc --version
nvidia-smi
```

### Windows Installation (WSL2)

1. **Install WSL2** with Ubuntu
2. **Install NVIDIA drivers** on Windows host
3. **Follow Ubuntu installation steps** above within WSL2
4. **Verify CUDA** works in WSL2 environment

## Building

### Build Performance-Optimized Version (Default)
```bash
make -f Makefile.hybrid
```

### Clean Build Files
```bash
make -f Makefile.hybrid clean
```

### Install Dependencies
```bash
make -f Makefile.hybrid install-deps
```

### Check CUDA Installation
```bash
make -f Makefile.hybrid check-cuda
```

## Usage

### Run the Program
```bash
./mckeysearcher_hybrid
```

### Program Flow
1. **Enter hex prefix**: Specify the prefix to search for (e.g., BEEF, 1234)
2. **Choose search mode**:
   - 1: Prefix only
   - 2: Suffix only  
   - 3: Prefix + Suffix
3. **Enter suffix** (if mode 2 or 3 selected)
4. **Choose search behavior**:
   - 1: Find one key
   - 2: Find N keys
   - 3: Continuous search
5. **Monitor progress**: Real-time performance metrics
6. **Results saved**: Found keys are saved to `found_keys.txt`


## Performance

### Expected Performance
- **CPU Only**: ~500k-800k keys/sec (when CUDA unavailable)
- **Hybrid CPU+GPU**: ~1.5M+ keys/sec with spikes to 2M+ (GPU generates random + CPU computes Ed25519)

### Performance Factors
- **CPU**: Number of cores, AVX-512 support, NUMA configuration
- **GPU**: CUDA compute capability, memory bandwidth
- **System**: Memory speed, storage I/O, thermal throttling

## Configuration

### CPU Threads
- Automatically detects available cores
- Reserves one core for OS by default
- Can be modified in the source code

### Batch Sizes
- **CPU**: 32,768 keys per batch (optimized for AVX-512)
- **GPU**: 131,072 keys per batch (CUDA optimized)

### NUMA Settings
- Automatically detects NUMA nodes
- Allocates memory on appropriate nodes
- Thread affinity to specific CPU cores



**Windows/WSL2 Issues**
- Ensure NVIDIA drivers are installed on Windows host
- Verify CUDA works in WSL2: `nvidia-smi` should show GPU
- If CUDA not detected, restart WSL2: `wsl --shutdown` then restart




### Architecture
- **CPU Workers**: Multi-threaded with NUMA awareness, generates complete Ed25519 keys
- **GPU Workers**: CUDA kernels for parallel random number generation only
- **Hybrid Coordination**: GPU generates random material, CPU computes Ed25519 keys

### Cryptographic Implementation
- **Ed25519**: libsodium's optimized implementation
- **Random Generation**: GPU-accelerated cuRAND + libsodium fallback
- **Key Format**: 64-byte private keys, 32-byte public keys
- **Hybrid Approach**: GPU generates random material, CPU computes Ed25519 keys

### Memory Management
- **NUMA-aware allocation**: Memory allocated on appropriate nodes
- **Batch processing**: Efficient memory usage with large batches
- **Cache optimization**: Prefetching and alignment for performance

## License

This project is provided as-is for educational and research purposes. Use at your own risk.
