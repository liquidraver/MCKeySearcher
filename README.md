# MCKeySearcher - Hybrid CPU+GPU Ed25519 Key Searcher

A high-performance Ed25519 key searcher that combines CPU and GPU acceleration for maximum performance. Optimized for server environments with NUMA support and AVX-512 optimizations.

## Features

- **Hybrid CPU+GPU**: Combines both CPU and GPU for maximum performance
- **Server Optimized**: NUMA-aware memory allocation and thread affinity
- **Multiple Search Modes**: Prefix only, suffix only, or prefix+suffix
- **High Performance**: Achieves ~1.5M keys/sec with 2M+ spikes on optimized systems
- **Cryptographically Secure**: Uses libsodium's proven Ed25519 implementation
- **NUMA Support**: Optimized for multi-socket systems

## Requirements

- Ubuntu 24.04 (recommended) or Ubuntu 22.04
- CUDA-capable GPU (GTX 1080 or better recommended)
- CUDA toolkit 12.5 or later
- 64-bit system with AVX-512 support (for maximum performance)

## Installation on Fresh Ubuntu

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
# Add NVIDIA repository for Ubuntu 24.04
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-ubuntu2404.pin
sudo mv cuda-ubuntu2404.pin /etc/apt/preferences.d/cuda-repository-pin-600
sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/3bf863cc.pub
sudo add-apt-repository "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/ /"

# Install CUDA
sudo apt update
sudo apt install -y cuda-toolkit-12-5
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

## Building

### Build with Server Optimizations (Recommended)
```bash
make -f Makefile.hybrid server
```

### Build with Standard Optimizations
```bash
make -f Makefile.hybrid perf
```

### Build Debug Version
```bash
make -f Makefile.hybrid debug
```

### Clean Build Files
```bash
make -f Makefile.hybrid clean
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

### Example Session
```
Enter hex prefix (e.g., BEEF, 1234): BEEF

Search mode:
1. Prefix only
2. Suffix only
3. Prefix + Suffix
Choice (1-3): 1

Search behavior:
1. Find one key
2. Find N keys
3. Continuous
Choice (1-3): 1

Starting hybrid CPU+GPU search...
Found keys will be saved to found_keys.txt
```

## Performance

### Expected Performance
- **CPU Only**: ~500k-800k keys/sec (depending on system)
- **GPU Only**: ~1M-2M keys/sec (depending on GPU)
- **Hybrid**: ~1.5M+ keys/sec with spikes to 2M+

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
- **GPU**: 32,768 keys per batch (CUDA optimized)

### NUMA Settings
- Automatically detects NUMA nodes
- Allocates memory on appropriate nodes
- Thread affinity to specific CPU cores

## Troubleshooting

### Common Issues

**"CUDA not found"**
```bash
# Verify CUDA installation
nvcc --version
nvidia-smi

# Check environment variables
echo $PATH | grep cuda
echo $LD_LIBRARY_PATH | grep cuda
```

**"libsodium not found"**
```bash
sudo apt install libsodium-dev
```

**"libnuma not found"**
```bash
sudo apt install libnuma-dev
```

**"mbind: Invalid argument" warnings**
- These are normal in VMware environments
- Program continues to work optimally
- Can be safely ignored

**Build failures**
```bash
# Clean and rebuild
make -f Makefile.hybrid clean
make -f Makefile.hybrid server
```

### Performance Issues

**Low CPU performance**
- Check if AVX-512 is supported: `cat /proc/cpuinfo | grep avx512`
- Verify NUMA configuration: `numactl --hardware`
- Check thermal throttling: `cat /proc/cpuinfo | grep MHz`

**Low GPU performance**
- Verify CUDA driver: `nvidia-smi`
- Check GPU utilization: `nvidia-smi dmon`
- Monitor GPU temperature and power limits

## File Structure

```
MCKeySearcher/
├── main_hybrid.cpp          # Main source code
├── Makefile.hybrid          # Build system
├── mckeysearcher_hybrid     # Compiled executable
└── found_keys.txt           # Output file (created when keys found)
```

## Technical Details

### Architecture
- **CPU Workers**: Multi-threaded with NUMA awareness
- **GPU Workers**: CUDA kernels for parallel key generation
- **Hybrid Coordination**: Shared state management and progress tracking

### Cryptographic Implementation
- **Ed25519**: libsodium's optimized implementation
- **Random Generation**: libsodium's secure random number generator
- **Key Format**: 64-byte private keys, 32-byte public keys

### Memory Management
- **NUMA-aware allocation**: Memory allocated on appropriate nodes
- **Batch processing**: Efficient memory usage with large batches
- **Cache optimization**: Prefetching and alignment for performance

## License

This project is provided as-is for educational and research purposes. Use at your own risk.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify your system meets the requirements
3. Ensure all dependencies are properly installed
4. Check that CUDA is working correctly
