#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>
#include <string>
#include <cstring>
#include <cmath>
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <pthread.h>
#include <numa.h>
#include <immintrin.h>

// CUDA error checking macro
#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        std::cerr << "CUDA error at " << __FILE__ << ":" << __LINE__ << " - " \
                  << cudaGetErrorString(err) << std::endl; \
        exit(1); \
    } \
} while(0)

// Configuration
struct Config {
    std::string prefix;
    std::string suffix;  // For suffix-only or prefix+suffix searches
    int search_mode = 1; // 1: prefix only, 2: suffix only, 3: prefix + suffix
    int target_keys = 1;
    bool continuous = false;
    bool use_gpu = true;
    bool use_cpu = true;
    int cpu_threads = 0; // Will be set automatically
    bool numa_aware = true;
    size_t batch_size = 32768; // Larger batches for AVX-512 optimized CPUs
};

// Global state
std::atomic<uint64_t> total_attempts(0);
std::atomic<int> keys_found(0);
std::atomic<bool> stop_search(false);
std::mutex file_mutex;
std::mutex print_mutex;

// NUMA-aware memory allocation for 2-socket setup
struct NumaBuffer {
    std::vector<unsigned char> seeds;
    std::vector<unsigned char> pubkeys;
    std::vector<unsigned char> privkeys;
    int numa_node;
    
    NumaBuffer(size_t size, int node) : numa_node(node) {
        // Allocate memory on specific NUMA node
        if (numa_available() >= 0) {
            seeds.resize(size * 32);
            pubkeys.resize(size * 32);
            privkeys.resize(size * 64);
            
            // Try to bind memory to NUMA node - this may fail in VMware environments
            // but we continue anyway since memory allocation succeeded
            numa_tonode_memory(seeds.data(), seeds.size(), node);
            numa_tonode_memory(pubkeys.data(), pubkeys.size(), node);
            numa_tonode_memory(privkeys.data(), privkeys.size(), node);
            
            // Note: numa_tonode_memory returns void, so we can't check for errors
            // In VMware environments, this may generate "mbind: Invalid argument" warnings
            // but the program continues to work optimally
        } else {
            seeds.resize(size * 32);
            pubkeys.resize(size * 32);
            privkeys.resize(size * 64);
        }
    }
};

// Fast hex conversion
static const char hex_chars[] = "0123456789ABCDEF";

inline void to_hex_fast(const unsigned char* data, size_t len, std::string& out) {
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hex_chars[data[i] >> 4];
        out[2 * i + 1] = hex_chars[data[i] & 0x0F];
    }
}

// Fast prefix checking
inline bool check_prefix(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    for (size_t i = 0; i < prefix_len; ++i) {
        unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
        unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
        unsigned char expected = (high << 4) | low;
        if (data[i] != expected) return false;
    }
    return true;
}

// Fast suffix checking
inline bool check_suffix(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    size_t start_byte = 32 - prefix_len;
    for (size_t i = 0; i < prefix_len; ++i) {
        unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
        unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
        unsigned char expected = (high << 4) | low;
        if (data[start_byte + i] != expected) return false;
    }
    return true;
}

// Log found key
void log_key(const std::string& priv_hex, const std::string& pub_hex, const std::string& label) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream out("found_keys.txt", std::ios::app);
    if (out.is_open()) {
        out << label << ": " << priv_hex << " | " << pub_hex << std::endl;
    }
}

// Set thread affinity to specific CPU core with NUMA awareness
void set_thread_affinity(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    pthread_t current_thread = pthread_self();
    int result = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        // Don't print warnings for every thread, just log the first few failures
        static int warning_count = 0;
        if (warning_count < 5) {
            std::cerr << "Warning: Failed to set affinity for thread to CPU " << cpu_id 
                      << " (error " << result << ")" << std::endl;
            warning_count++;
        }
    }
}

// Get NUMA node for CPU core
int get_numa_node(int cpu_id) {
    if (numa_available() >= 0) {
        return numa_node_of_cpu(cpu_id);
    }
    return 0;
}

// Print status
void print_status(uint64_t attempts, int found, double keys_per_sec, const std::string& source) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\r[" << source << "] Attempts: " << attempts 
              << " | Found: " << found 
              << " | Keys/sec: " << std::fixed << std::setprecision(0) << keys_per_sec
              << "          " << std::flush;
}

// CUDA wrapper function declarations
extern "C" cudaError_t call_generate_ed25519_keys_kernel(
    curandState* d_states,
    uint8_t* d_seeds,
    uint8_t* d_pubkeys,
    uint8_t* d_privkeys,
    int batch_size,
    int block_size,
    int grid_size
);

// GPU worker thread
void gpu_worker(const Config& config, int thread_id) {
    const size_t BATCH_SIZE = 32768; // Larger batches for GPU
    
    // Allocate GPU memory
    curandState* d_states;
    unsigned char *d_seeds, *d_pubkeys, *d_privkeys;
    
    CUDA_CHECK(cudaMalloc(&d_states, BATCH_SIZE * sizeof(curandState)));
    CUDA_CHECK(cudaMalloc(&d_seeds, BATCH_SIZE * 32));
    CUDA_CHECK(cudaMalloc(&d_pubkeys, BATCH_SIZE * 32));
    CUDA_CHECK(cudaMalloc(&d_privkeys, BATCH_SIZE * 64));
    
    // Allocate host memory
    std::vector<unsigned char> h_seeds(BATCH_SIZE * 32);
    std::vector<unsigned char> h_pubkeys(BATCH_SIZE * 32);
    std::vector<unsigned char> h_privkeys(BATCH_SIZE * 64);
    
    // Initialize CUDA random states
    curandState* h_states = new curandState[BATCH_SIZE];
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        curand_init(1234 + i + thread_id * 1000, 0, 0, &h_states[i]);
    }
    CUDA_CHECK(cudaMemcpy(d_states, h_states, BATCH_SIZE * sizeof(curandState), cudaMemcpyHostToDevice));
    delete[] h_states;
    
    // CUDA grid configuration
    int block_size = 256;
    int grid_size = (BATCH_SIZE + block_size - 1) / block_size;
    
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    uint64_t local_attempts = 0;
    const int UPDATE_INTERVAL = 1000;
    
    while (!stop_search.load()) {
        // Generate keys on GPU
        CUDA_CHECK(call_generate_ed25519_keys_kernel(
            d_states, (uint8_t*)d_seeds, (uint8_t*)d_pubkeys, (uint8_t*)d_privkeys, 
            BATCH_SIZE, block_size, grid_size
        ));
        CUDA_CHECK(cudaDeviceSynchronize());
        
        // Copy results back to host
        CUDA_CHECK(cudaMemcpy(h_seeds.data(), d_seeds, BATCH_SIZE * 32, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(h_pubkeys.data(), d_pubkeys, BATCH_SIZE * 32, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(h_privkeys.data(), d_privkeys, BATCH_SIZE * 64, cudaMemcpyDeviceToHost));
        
        // Process results
        for (size_t i = 0; i < BATCH_SIZE; ++i) {
            if (stop_search.load()) break;
            
            local_attempts++;
            
            bool prefix_match = check_prefix(&h_pubkeys[i * 32], config.prefix);
            
            if (prefix_match) {
                to_hex_fast(&h_privkeys[i * 64], 64, priv_hex);
                to_hex_fast(&h_pubkeys[i * 32], 32, pub_hex);
                
                if (config.search_mode == 2 && check_suffix(&h_pubkeys[i * 32], config.prefix)) {
                    log_key(priv_hex, pub_hex, "GPU-Prefix+Suffix");
                } else {
                    log_key(priv_hex, pub_hex, "GPU-Prefix");
                }
                
                keys_found.fetch_add(1);
                
                if (!config.continuous && keys_found.load() >= config.target_keys) {
                    stop_search.store(true);
                    break;
                }
            }
            
            if (local_attempts % UPDATE_INTERVAL == 0) {
                total_attempts.fetch_add(local_attempts);
                local_attempts = 0;
            }
        }
        
        if (local_attempts > 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
    
    // Cleanup GPU memory
    CUDA_CHECK(cudaFree(d_states));
    CUDA_CHECK(cudaFree(d_seeds));
    CUDA_CHECK(cudaFree(d_pubkeys));
    CUDA_CHECK(cudaFree(d_privkeys));
}

// Server-optimized CPU worker thread for Xeon Gold 5220
void cpu_worker(const Config& config, int thread_id, int cpu_id) {
    // Set thread affinity to specific CPU core
    set_thread_affinity(cpu_id);
    
    // Get NUMA node for this CPU
    int numa_node = get_numa_node(cpu_id);
    
    // Allocate NUMA-aware buffers
    NumaBuffer buffers(config.batch_size, numa_node);
    
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    uint64_t local_attempts = 0;
    const int UPDATE_INTERVAL = 1000;
    
    // Pre-fetch buffers into cache
    __builtin_prefetch(buffers.seeds.data(), 0, 3);
    __builtin_prefetch(buffers.pubkeys.data(), 1, 3);
    __builtin_prefetch(buffers.privkeys.data(), 1, 3);
    
    while (!stop_search.load()) {
        // Generate batch of keys
        for (size_t i = 0; i < config.batch_size; ++i) {
            randombytes_buf(&buffers.seeds[i * 32], 32);
            crypto_sign_ed25519_keypair(&buffers.pubkeys[i * 32], &buffers.privkeys[i * 64]);
        }
        
        // Process batch with cache optimization
        for (size_t i = 0; i < config.batch_size; ++i) {
            if (stop_search.load()) break;
            
            local_attempts++;
            
            // Pre-fetch next elements
            if (i + 64 < config.batch_size) {
                __builtin_prefetch(&buffers.pubkeys[(i + 64) * 32], 0, 1);
                __builtin_prefetch(&buffers.privkeys[(i + 64) * 64], 0, 1);
            }
            
            bool match = false;
            std::string match_type;
            
            // Check based on search mode
            if (config.search_mode == 1) {
                // Prefix only
                match = check_prefix(&buffers.pubkeys[i * 32], config.prefix);
                if (match) match_type = "CPU-Prefix";
            } else if (config.search_mode == 2) {
                // Suffix only
                match = check_suffix(&buffers.pubkeys[i * 32], config.suffix);
                if (match) match_type = "CPU-Suffix";
            } else if (config.search_mode == 3) {
                // Prefix + Suffix
                bool prefix_match = check_prefix(&buffers.pubkeys[i * 32], config.prefix);
                bool suffix_match = check_suffix(&buffers.pubkeys[i * 32], config.suffix);
                match = prefix_match && suffix_match;
                if (match) match_type = "CPU-Prefix+Suffix";
            }
            
            if (match) {
                to_hex_fast(&buffers.privkeys[i * 64], 64, priv_hex);
                to_hex_fast(&buffers.pubkeys[i * 32], 32, pub_hex);
                
                log_key(priv_hex, pub_hex, match_type);
                
                keys_found.fetch_add(1);
                
                if (!config.continuous && keys_found.load() >= config.target_keys) {
                    stop_search.store(true);
                    break;
                }
            }
            
            if (local_attempts % UPDATE_INTERVAL == 0) {
                total_attempts.fetch_add(local_attempts);
                local_attempts = 0;
            }
        }
        
        if (local_attempts > 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
}

// Function declarations for CUDA functions
extern "C" void init_ed25519_constants();

// Performance test for both CPU and GPU
struct PerformanceResults {
    double cpu_keys_per_sec = 0;
    double gpu_keys_per_sec = 0;
    double total_keys_per_sec = 0;
};

PerformanceResults measure_hybrid_performance() {
    std::cout << "\nRunning hybrid performance test (5 seconds)..." << std::endl;
    
    const size_t TEST_BATCH = 32768;
    const int TEST_DURATION = 5;
    
    std::atomic<uint64_t> total_keys(0);
    std::vector<std::thread> threads;
    
    auto start = std::chrono::steady_clock::now();
    
    // Test GPU performance
    if (true) { // Always test GPU for now
        auto gpu_test_worker = [&]() {
            curandState* d_states;
            unsigned char *d_seeds, *d_pubkeys, *d_privkeys;
            
            CUDA_CHECK(cudaMalloc(&d_states, TEST_BATCH * sizeof(curandState)));
            CUDA_CHECK(cudaMalloc(&d_seeds, TEST_BATCH * 32));
            CUDA_CHECK(cudaMalloc(&d_pubkeys, TEST_BATCH * 32));
            CUDA_CHECK(cudaMalloc(&d_privkeys, TEST_BATCH * 64));
            
            curandState* h_states = new curandState[TEST_BATCH];
            for (size_t i = 0; i < TEST_BATCH; ++i) {
                curand_init(1234 + i, 0, 0, &h_states[i]);
            }
            CUDA_CHECK(cudaMemcpy(d_states, h_states, TEST_BATCH * sizeof(curandState), cudaMemcpyHostToDevice));
            delete[] h_states;
            
            int block_size = 256;
            int grid_size = (TEST_BATCH + block_size - 1) / block_size;
            
            uint64_t local_keys = 0;
            auto end_time = start + std::chrono::seconds(TEST_DURATION);
            
            while (std::chrono::steady_clock::now() < end_time) {
                CUDA_CHECK(call_generate_ed25519_keys_kernel(
                    d_states, (uint8_t*)d_seeds, (uint8_t*)d_pubkeys, (uint8_t*)d_privkeys,
                    TEST_BATCH, block_size, grid_size
                ));
                CUDA_CHECK(cudaDeviceSynchronize());
                local_keys += TEST_BATCH;
            }
            
            total_keys.fetch_add(local_keys);
            
            CUDA_CHECK(cudaFree(d_states));
            CUDA_CHECK(cudaFree(d_seeds));
            CUDA_CHECK(cudaFree(d_pubkeys));
            CUDA_CHECK(cudaFree(d_privkeys));
        };
        
        threads.emplace_back(gpu_test_worker);
    }
    
    // Test CPU performance
    if (true) { // Always test CPU for now
        auto cpu_test_worker = [&]() {
            std::vector<unsigned char> seeds(TEST_BATCH * 32);
            std::vector<unsigned char> pubkeys(TEST_BATCH * 32);
            std::vector<unsigned char> privkeys(TEST_BATCH * 64);
            
            uint64_t local_keys = 0;
            auto end_time = start + std::chrono::seconds(TEST_DURATION);
            
            while (std::chrono::steady_clock::now() < end_time) {
                for (size_t i = 0; i < TEST_BATCH; ++i) {
                    randombytes_buf(&seeds[i * 32], 32);
                    crypto_sign_ed25519_keypair(&pubkeys[i * 32], &privkeys[i * 64]);
                }
                local_keys += TEST_BATCH;
            }
            
            total_keys.fetch_add(local_keys);
        };
        
        threads.emplace_back(cpu_test_worker);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    PerformanceResults results;
    results.total_keys_per_sec = total_keys.load() / elapsed.count();
    
    // Estimate individual performance (this is approximate)
    results.gpu_keys_per_sec = results.total_keys_per_sec * 0.7; // GPU typically 70% of total
    results.cpu_keys_per_sec = results.total_keys_per_sec * 0.3; // CPU typically 30% of total
    
    std::cout << "Hybrid Performance: " << std::fixed << std::setprecision(0) 
              << results.total_keys_per_sec << " keys/sec total" << std::endl;
    std::cout << "Estimated GPU: " << std::fixed << std::setprecision(0) 
              << results.gpu_keys_per_sec << " keys/sec" << std::endl;
    std::cout << "Estimated CPU: " << std::fixed << std::setprecision(0) 
              << results.cpu_keys_per_sec << " keys/sec" << std::endl;
    
    return results;
}

// Main function
int main(int argc, char* argv[]) {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    // Initialize CUDA
    CUDA_CHECK(cudaSetDevice(0));
    
    // Initialize Ed25519 constants
    init_ed25519_constants();
    
    int device_count;
    CUDA_CHECK(cudaGetDeviceCount(&device_count));
    if (device_count == 0) {
        std::cerr << "No CUDA devices found!" << std::endl;
        return 1;
    }
    
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    std::cout << "🔍 MCKeySearcher - Hybrid CPU+GPU Ed25519 Key Searcher\n";
    std::cout << "🚀 Using GPU: " << prop.name << "\n";
    std::cout << "   Compute Capability: " << prop.major << "." << prop.minor << "\n";
    std::cout << "   Memory: " << (prop.totalGlobalMem / (1024*1024*1024)) << " GB\n\n";
    
    // Get prefix
    std::string prefix;
    std::cout << "Enter hex prefix (e.g., BEEF, 1234): ";
    std::cin >> prefix;
    
    if (prefix.empty()) {
        std::cout << "No prefix specified." << std::endl;
        return 1;
    }
    
    // Validate prefix
    for (char c : prefix) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            std::cout << "Invalid hex prefix. Use only 0-9, A-F." << std::endl;
            return 1;
        }
    }
    
    // Convert to uppercase
    for (char& c : prefix) {
        if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
    }
    
    Config config;
    config.prefix = prefix;
    
    // Get search mode
    std::cout << "\nSearch mode:\n";
    std::cout << "1. Prefix only\n";
    std::cout << "2. Suffix only\n";
    std::cout << "3. Prefix + Suffix\n";
    std::cout << "Choice (1-3): ";
    std::cin >> config.search_mode;
    
    if (config.search_mode < 1 || config.search_mode > 3) {
        config.search_mode = 1;
    }
    
    // Get suffix if needed
    if (config.search_mode == 2 || config.search_mode == 3) {
        std::cout << "\nEnter hex suffix (e.g., BEEF, 1234): ";
        std::cin >> config.suffix;
        
        if (config.suffix.empty()) {
            std::cout << "No suffix specified, defaulting to prefix only." << std::endl;
            config.search_mode = 1;
        } else {
            // Validate and convert suffix to uppercase
            for (char& c : config.suffix) {
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                    std::cout << "Invalid hex suffix. Use only 0-9, A-F." << std::endl;
                    return 1;
                }
                if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
            }
        }
    }
    
    // Get search behavior
    std::cout << "\nSearch behavior:\n";
    std::cout << "1. Find one key\n";
    std::cout << "2. Find N keys\n";
    std::cout << "3. Continuous\n";
    std::cout << "Choice (1-3): ";
    
    int behavior;
    std::cin >> behavior;
    
    switch (behavior) {
        case 1:
            config.continuous = false;
            config.target_keys = 1;
            break;
        case 2:
            std::cout << "Number of keys to find: ";
            std::cin >> config.target_keys;
            config.continuous = false;
            break;
        case 3:
            config.continuous = true;
            config.target_keys = 0;
            break;
        default:
            config.continuous = false;
            config.target_keys = 1;
            break;
    }
    
    // Calculate optimal thread distribution
    unsigned int total_cores = std::thread::hardware_concurrency();
    config.cpu_threads = (total_cores > 1) ? total_cores - 1 : 1; // Leave one core for OS
    
    std::cout << "\nSystem Info:\n";
    std::cout << "Total CPU cores: " << total_cores << "\n";
    std::cout << "CPU threads to use: " << config.cpu_threads << " (1 core reserved for OS)\n";
    std::cout << "Search mode: ";
    if (config.search_mode == 1) {
        std::cout << "Prefix only (" << config.prefix << ")";
    } else if (config.search_mode == 2) {
        std::cout << "Suffix only (" << config.suffix << ")";
    } else {
        std::cout << "Prefix + Suffix (" << config.prefix << " + " << config.suffix << ")";
    }
    std::cout << "\nGPU: " << prop.name << "\n\n";
    
    // Measure hybrid performance
    PerformanceResults perf = measure_hybrid_performance();
    
    // Calculate expected time
    size_t prefix_len = prefix.length() / 2;
    double combinations = pow(16.0, prefix_len);
    double expected_time = combinations / perf.total_keys_per_sec;
    
    std::cout << "\nExpected time for prefix '" << prefix << "': ";
    if (expected_time < 60) {
        std::cout << std::fixed << std::setprecision(1) << expected_time << " seconds";
    } else if (expected_time < 3600) {
        std::cout << std::fixed << std::setprecision(1) << (expected_time / 60) << " minutes";
    } else if (expected_time < 86400) {
        std::cout << std::fixed << std::setprecision(1) << (expected_time / 3600) << " hours";
    } else {
        std::cout << std::fixed << std::setprecision(1) << (expected_time / 86400) << " days";
    }
    std::cout << std::endl;
    
    // Start hybrid search
    std::cout << "\nStarting hybrid CPU+GPU search...\n";
    std::cout << "Found keys will be saved to found_keys.txt\n\n";
    
    std::vector<std::thread> threads;
    
    // Start GPU worker
    if (config.use_gpu) {
        threads.emplace_back(gpu_worker, std::ref(config), 0);
        std::cout << "Started GPU worker thread\n";
    }
    
    // Start CPU workers
    if (config.use_cpu) {
        for (int i = 0; i < config.cpu_threads; ++i) {
            threads.emplace_back(cpu_worker, std::ref(config), i, i);
        }
        std::cout << "Started " << config.cpu_threads << " CPU worker threads\n";
    }
    
    // Monitor progress
    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_search.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        uint64_t current_attempts = total_attempts.load();
        int current_found = keys_found.load();
        auto now = std::chrono::steady_clock::now();
        
        std::chrono::duration<double> elapsed = now - last_time;
        double keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        print_status(current_attempts, current_found, keys_per_sec, "HYBRID");
        
        last_attempts = current_attempts;
        last_time = now;
        
        if (!config.continuous && current_found >= config.target_keys) {
            stop_search.store(true);
            break;
        }
    }
    
    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();
    }
    
    std::cout << "\n\nSearch completed! Found " << keys_found.load() << " keys." << std::endl;
    std::cout << "Keys saved to found_keys.txt" << std::endl;
    
    return 0;
}

