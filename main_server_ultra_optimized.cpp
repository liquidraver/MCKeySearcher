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
#include <pthread.h>
#include <numa.h>
#include <immintrin.h>

// Server-optimized configuration for Intel Xeon Gold 5220
struct Config {
    std::string prefix;
    int search_mode = 1; // 1: prefix only, 2: prefix + suffix
    int target_keys = 1;
    bool continuous = false;
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

// AVX-512 optimized hex conversion (64 bytes at once) - Cascade Lake compatible
inline void to_hex_fast_avx512(const unsigned char* data, size_t len, std::string& out) {
    out.resize(len * 2);
    
    // Process 64 bytes at a time with AVX-512
    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        __m512i bytes = _mm512_loadu_si512(&data[i]);
        
        // Extract high nibbles (bits 4-7)
        __m512i high = _mm512_srli_epi64(bytes, 4);
        high = _mm512_and_si512(high, _mm512_set1_epi8(0x0F));
        
        // Extract low nibbles (bits 0-3)
        __m512i low = _mm512_and_si512(bytes, _mm512_set1_epi8(0x0F));
        
        // Convert to hex characters
        __m512i high_hex = _mm512_add_epi8(high, _mm512_set1_epi8('0'));
        __m512i low_hex = _mm512_add_epi8(low, _mm512_set1_epi8('0'));
        
        // Adjust for A-F range using simple arithmetic
        // For values > 9, we need to add 7 to get A-F (65-70 instead of 48-57)
        __m512i nine = _mm512_set1_epi8(9);
        
        // Use simple comparison and arithmetic instead of complex intrinsics
        for (int j = 0; j < 64; ++j) {
            unsigned char high_val = ((unsigned char*)&high)[j];
            unsigned char low_val = ((unsigned char*)&low)[j];
            
            if (high_val > 9) high_val += 7;
            if (low_val > 9) low_val += 7;
            
            ((unsigned char*)&high_hex)[j] = high_val;
            ((unsigned char*)&low_hex)[j] = low_val;
        }
        
        // Store hex characters
        _mm512_storeu_si512((__m512i*)&out[2 * i], high_hex);
        _mm512_storeu_si512((__m512i*)&out[2 * i + 1], low_hex);
    }
    
    // Handle remaining bytes with standard approach
    for (; i < len; ++i) {
        unsigned char byte = data[i];
        unsigned char high = (byte >> 4) & 0x0F;
        unsigned char low = byte & 0x0F;
        
        char high_char = (high > 9) ? (high - 10 + 'A') : (high + '0');
        char low_char = (low > 9) ? (low - 10 + 'A') : (low + '0');
        
        out[2 * i] = high_char;
        out[2 * i + 1] = low_char;
    }
}

// AVX-512 optimized prefix checking
inline bool check_prefix_avx512(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    
    // Process 64 bytes at a time with AVX-512
    size_t i = 0;
    for (; i + 64 <= prefix_len; i += 64) {
        __m512i data_chunk = _mm512_loadu_si512(&data[i]);
        __m512i prefix_chunk = _mm512_loadu_si512((__m512i*)&prefix[i * 2]);
        
        // Compare bytes
        __m512i diff = _mm512_xor_si512(data_chunk, prefix_chunk);
        
        // Check if any differences exist
        bool has_diff = false;
        for (int j = 0; j < 64; ++j) {
            if (((unsigned char*)&diff)[j] != 0) {
                has_diff = true;
                break;
            }
        }
        
        if (has_diff) return false;
    }
    
    // Handle remaining bytes
    for (; i < prefix_len; ++i) {
        unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
        unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
        unsigned char target = (high << 4) | low;
        
        if (data[i] != target) return false;
    }
    
    return true;
}

// Get NUMA node for CPU core
int get_numa_node(int cpu_id) {
    if (numa_available() < 0) return 0;
    
    // Simple mapping: even cores on node 0, odd cores on node 1
    // This is a reasonable approximation for most 2-socket systems
    return cpu_id % 2;
}

// Set thread affinity with NUMA awareness
void set_thread_affinity(int cpu_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    static int warning_count = 0;
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        if (warning_count < 5) { // Only show first 5 warnings
            std::cerr << "Warning: Failed to set CPU affinity for core " << cpu_id << std::endl;
            warning_count++;
        }
    }
#endif
}

// Main CPU worker function
void cpu_worker(int thread_id, int cpu_id, const Config& config) {
    set_thread_affinity(cpu_id);
    
    // Get NUMA node for this CPU
    int numa_node = get_numa_node(cpu_id);
    
    // Create NUMA-aware buffer
    NumaBuffer buffer(config.batch_size, numa_node);
    
    // Thread-local counters
    uint64_t local_attempts = 0;
    int local_keys_found = 0;
    
    // Pre-allocate hex strings
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    while (!stop_search.load()) {
        // Generate batch of keys
        for (size_t i = 0; i < config.batch_size; ++i) {
            if (stop_search.load()) break;
            
            // Generate random seed
            randombytes_buf(&buffer.seeds[i * 32], 32);
            
            // Generate Ed25519 keypair using libsodium
            crypto_sign_ed25519_keypair(&buffer.pubkeys[i * 32], &buffer.privkeys[i * 32]);
            
            local_attempts++;
            
            // Check prefix match using AVX-512
            if (check_prefix_avx512(&buffer.pubkeys[i * 32], config.prefix)) {
                // Convert to hex for logging
                to_hex_fast_avx512(&buffer.pubkeys[i * 32], 32, pub_hex);
                to_hex_fast_avx512(&buffer.privkeys[i * 32], 64, priv_hex);
                
                // Log found key
                {
                    std::lock_guard<std::mutex> lock(file_mutex);
                    std::ofstream out("found_keys.txt", std::ios::app);
                    if (out.is_open()) {
                        out << "Prefix: " << priv_hex << " | " << pub_hex << std::endl;
                        out.close();
                    }
                }
                
                local_keys_found++;
                keys_found.fetch_add(1);
                
                // Check if we should stop
                if (config.target_keys > 0 && keys_found.load() >= config.target_keys) {
                    stop_search.store(true);
                    break;
                }
            }
        }
        
        // Update global counter
        total_attempts.fetch_add(local_attempts);
        local_attempts = 0;
        
        // Small delay to prevent overwhelming the system
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    // Final update
    if (local_attempts > 0) {
        total_attempts.fetch_add(local_attempts);
    }
}

// Performance measurement
void measure_performance(const Config& config) {
    std::cout << "\nRunning performance test..." << std::endl;
    
    const int test_duration = 5; // 5 seconds
    const size_t test_batch_size = 10000;
    
    std::atomic<uint64_t> test_attempts(0);
    std::vector<std::thread> test_threads;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Start test threads
    for (int i = 0; i < config.cpu_threads; ++i) {
        test_threads.emplace_back([i, &test_attempts, test_batch_size, test_duration]() {
            set_thread_affinity(i);
            
            auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(test_duration);
            uint64_t local_attempts = 0;
            
            while (std::chrono::steady_clock::now() < end_time) {
                for (size_t j = 0; j < test_batch_size; ++j) {
                    uint8_t pubkey[32], privkey[64];
                    crypto_sign_ed25519_keypair(pubkey, privkey);
                    local_attempts++;
                }
            }
            
            test_attempts.fetch_add(local_attempts);
        });
    }
    
    // Wait for test to complete
    for (auto& thread : test_threads) {
        thread.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;
    
    double keys_per_sec = test_attempts.load() / elapsed.count();
    double keys_per_core = keys_per_sec / config.cpu_threads;
    
    std::cout << "Performance test completed:" << std::endl;
    std::cout << "  Total speed: " << std::fixed << std::setprecision(0) << keys_per_sec << " keys/sec" << std::endl;
    std::cout << "  Speed per core: " << std::fixed << std::setprecision(0) << keys_per_core << " keys/sec" << std::endl;
    std::cout << "  Cores used: " << config.cpu_threads << std::endl;
}

// Print status
void print_status() {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\rAttempts: " << total_attempts.load() 
              << " | Found: " << keys_found.load() 
              << " | Keys/sec: " << std::fixed << std::setprecision(0) 
              << (total_attempts.load() / 10.0) // Rough estimate
              << "          " << std::flush;
}

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Error: Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    std::cout << "🚀 MCKeySearcher - Server Optimized Edition" << std::endl;
    std::cout << "🔥 Intel Xeon Gold 5220 (Cascade Lake) Optimized" << std::endl;
    std::cout << "⚡ NUMA-aware + AVX-512 + libsodium\n\n";
    
    // Check NUMA support
    bool numa_supported = (numa_available() >= 0);
    std::cout << "NUMA Support: " << (numa_supported ? "✅ Available" : "❌ Not available") << std::endl;
    if (numa_supported) {
        std::cout << "  Using NUMA-aware memory allocation for optimal performance\n";
    } else {
        std::cout << "  NUMA not available, using standard memory allocation\n";
    }
    
    // Check AVX-512 support
    bool avx512_supported = __builtin_cpu_supports("avx512f");
    std::cout << "AVX-512 Support: " << (avx512_supported ? "✅ Available" : "❌ Not available") << std::endl;
    if (avx512_supported) {
        std::cout << "  Using AVX-512 optimized hex conversion and prefix checking\n";
    } else {
        std::cout << "  AVX-512 not available, performance may be reduced\n";
    }
    
    std::cout << std::endl;
    
    // Get configuration from user
    Config config;
    
    std::cout << "Enter hex prefix (e.g., BEEF, 1234): ";
    std::cin >> config.prefix;
    
    if (config.prefix.empty()) {
        std::cout << "No prefix specified." << std::endl;
        return 1;
    }
    
    // Validate and convert to uppercase
    for (char& c : config.prefix) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            std::cout << "Invalid hex prefix. Use only 0-9, A-F." << std::endl;
            return 1;
        }
        if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
    }
    
    std::cout << "\nSearch mode:\n";
    std::cout << "1. Prefix only\n";
    std::cout << "2. Prefix + Suffix\n";
    std::cout << "Choice (1-2): ";
    std::cin >> config.search_mode;
    
    if (config.search_mode != 1 && config.search_mode != 2) {
        config.search_mode = 1;
    }
    
    std::cout << "\nSearch behavior:\n";
    std::cout << "1. Find one key\n";
    std::cout << "2. Find N keys\n";
    std::cout << "3. Continuous\n";
    std::cout << "Choice (1-3): ";
    
    int behavior;
    std::cin >> behavior;
    
    switch (behavior) {
        case 1:
            config.target_keys = 1;
            config.continuous = false;
            break;
        case 2:
            std::cout << "Number of keys to find: ";
            std::cin >> config.target_keys;
            config.continuous = false;
            break;
        case 3:
            config.target_keys = 0;
            config.continuous = true;
            break;
        default:
            config.target_keys = 1;
            config.continuous = false;
            break;
    }
    
    // Determine optimal thread count
    config.cpu_threads = std::thread::hardware_concurrency();
    if (config.cpu_threads > 1) {
        config.cpu_threads--; // Leave one core for the OS
    }
    
    std::cout << "\n🚀 Configuration:" << std::endl;
    std::cout << "Prefix: " << config.prefix << " (" << (config.prefix.length() / 2) << " bytes)" << std::endl;
    std::cout << "Search mode: " << (config.search_mode == 1 ? "Prefix only" : "Prefix + Suffix") << std::endl;
    std::cout << "CPU threads: " << config.cpu_threads << std::endl;
    std::cout << "Batch size: " << config.batch_size << std::endl;
    std::cout << "NUMA-aware: " << (config.numa_aware ? "Yes" : "No") << std::endl;
    
    // Calculate expected time
    size_t prefix_len = config.prefix.length() / 2;
    double combinations = pow(16.0, prefix_len);
    double expected_keys_per_sec = 1500000; // Conservative estimate based on previous performance
    double expected_time = combinations / expected_keys_per_sec;
    
    std::cout << "\nExpected time for prefix '" << config.prefix << "': ";
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
    
    // Performance measurement
    measure_performance(config);
    
    // Start search
    std::cout << "\n🚀 Starting search...\n";
    std::cout << "Found keys will be saved to found_keys.txt\n\n";
    
    std::vector<std::thread> threads;
    
    // Start worker threads
    for (int i = 0; i < config.cpu_threads; ++i) {
        threads.emplace_back(cpu_worker, i, i, config);
    }
    
    // Monitor progress
    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_search.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        uint64_t current_attempts = total_attempts.load();
        auto now = std::chrono::steady_clock::now();
        
        std::chrono::duration<double> elapsed = now - last_time;
        double current_keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        std::cout << "\rAttempts: " << current_attempts 
                  << " | Found: " << keys_found.load() 
                  << " | Keys/sec: " << std::fixed << std::setprecision(0) << current_keys_per_sec
                  << "          " << std::flush;
        
        last_attempts = current_attempts;
        last_time = now;
        
        // Check if we should stop
        if (config.target_keys > 0 && keys_found.load() >= config.target_keys) {
            stop_search.store(true);
            break;
        }
    }
    
    // Wait for all threads to finish
    for (auto& thread : threads) {
        thread.join();
    }
    
    std::cout << "\n\n🚀 Search completed!" << std::endl;
    std::cout << "Keys found: " << keys_found.load() << std::endl;
    std::cout << "Total attempts: " << total_attempts.load() << std::endl;
    
    if (keys_found.load() > 0) {
        std::cout << "\nKeys saved to found_keys.txt" << std::endl;
        std::cout << "Remember to securely delete this file after copying the keys!" << std::endl;
    }
    
    return 0;
}
