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
            
            // Try to bind memory to NUMA node, but don't fail if it doesn't work
            int result1 = numa_tonode_memory(seeds.data(), seeds.size(), node);
            int result2 = numa_tonode_memory(pubkeys.data(), pubkeys.size(), node);
            int result3 = numa_tonode_memory(privkeys.data(), privkeys.size(), node);
            
            // If any binding fails, just continue without NUMA binding
            if (result1 < 0 || result2 < 0 || result3 < 0) {
                // Memory allocation succeeded, just NUMA binding failed
                // This is common in VMware environments
            }
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
        
        // Interleave high and low nibbles
        __m512i result = _mm512_unpacklo_epi8(high_hex, low_hex);
        
        // Store result
        _mm512_storeu_si512(&out[i * 2], result);
    }
    
    // Handle remaining bytes with standard method
    for (; i < len; ++i) {
        unsigned char high = (data[i] >> 4) & 0x0F;
        unsigned char low = data[i] & 0x0F;
        out[2 * i] = (high < 10) ? (high + '0') : (high - 10 + 'A');
        out[2 * i + 1] = (low < 10) ? (low + '0') : (low - 10 + 'A');
    }
}

// Fallback hex conversion for non-AVX-512
inline void to_hex_fast_fallback(const unsigned char* data, size_t len, std::string& out) {
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned char high = (data[i] >> 4) & 0x0F;
        unsigned char low = data[i] & 0x0F;
        out[2 * i] = (high < 10) ? (high + '0') : (high - 10 + 'A');
        out[2 * i + 1] = (low < 10) ? (low + '0') : (low - 10 + 'A');
    }
}

// Choose optimal hex conversion method
inline void to_hex_fast(const unsigned char* data, size_t len, std::string& out) {
    if (len >= 64) {
        to_hex_fast_avx512(data, len, out);
    } else {
        to_hex_fast_fallback(data, len, out);
    }
}

// AVX-512 optimized prefix checking (vectorized)
inline bool check_prefix_avx512(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    
    // Convert prefix to expected bytes
    std::vector<unsigned char> expected_bytes(prefix_len);
    for (size_t i = 0; i < prefix_len; ++i) {
        unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
        unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
        expected_bytes[i] = (high << 4) | low;
    }
    
    // Compare using AVX-512 if possible
    if (prefix_len >= 64) {
        // For very long prefixes, process 64 bytes at a time
        size_t i = 0;
        for (; i + 64 <= prefix_len; i += 64) {
            __m512i expected = _mm512_loadu_si512(&expected_bytes[i]);
            __m512i actual = _mm512_loadu_si512(&data[i]);
            
            // Use simple comparison - check if any bytes don't match
            __m512i diff = _mm512_xor_si512(expected, actual);
            
            // Check if any bytes are non-zero (simple byte-by-byte check)
            bool any_diff = false;
            for (int j = 0; j < 64; ++j) {
                if (((unsigned char*)&diff)[j] != 0) {
                    any_diff = true;
                    break;
                }
            }
            if (any_diff) {
                return false;
            }
        }
        
        // Handle remaining bytes
        for (; i < prefix_len; ++i) {
            if (data[i] != expected_bytes[i]) return false;
        }
        return true;
    } else {
        // For shorter prefixes, use standard method
        for (size_t i = 0; i < prefix_len; ++i) {
            if (data[i] != expected_bytes[i]) return false;
        }
        return true;
    }
}

// Fast prefix checking with fallback
inline bool check_prefix(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    
    if (prefix_len >= 64) {
        return check_prefix_avx512(data, prefix);
    } else {
        // Standard method for short prefixes
        for (size_t i = 0; i < prefix_len; ++i) {
            unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
            unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[i] != expected) return false;
            }
        return true;
    }
}

// Fast suffix checking (vectorized-friendly)
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

// Print status
void print_status(uint64_t attempts, int found, double keys_per_sec, const std::string& source) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\r[" << source << "] Attempts: " << attempts 
              << " | Found: " << found 
              << " | Keys/sec: " << std::fixed << std::setprecision(0) << keys_per_sec
              << "          " << std::flush;
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

// Server-optimized CPU worker thread for Xeon Gold 5220
void server_cpu_worker(const Config& config, int thread_id, int cpu_id) {
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
            
            bool prefix_match = check_prefix(&buffers.pubkeys[i * 32], config.prefix);
            
            if (prefix_match) {
                to_hex_fast(&buffers.privkeys[i * 64], 64, priv_hex);
                to_hex_fast(&buffers.pubkeys[i * 32], 32, pub_hex);
                
                if (config.search_mode == 2 && check_suffix(&buffers.pubkeys[i * 32], config.prefix)) {
                    log_key(priv_hex, pub_hex, "CPU-Prefix+Suffix");
                } else {
                    log_key(priv_hex, pub_hex, "CPU-Prefix");
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
}

// Performance test optimized for Xeon Gold 5220
double measure_server_performance(const Config& config) {
    std::cout << "\nRunning Xeon Gold 5220 performance test (5 seconds)..." << std::endl;
    
    const size_t TEST_BATCH = config.batch_size;
    const int TEST_DURATION = 5;
    
    std::atomic<uint64_t> total_keys(0);
    std::vector<std::thread> threads;
    
    auto start = std::chrono::steady_clock::now();
    
    // Test with multiple threads to simulate real workload
    int test_threads = std::min(config.cpu_threads, 24); // Test with more threads for 72-core system
    
    for (int i = 0; i < test_threads; ++i) {
        auto test_worker = [&, i]() {
            int cpu_id = i % config.cpu_threads;
            set_thread_affinity(cpu_id);
            
            NumaBuffer buffers(TEST_BATCH, get_numa_node(cpu_id));
            
            uint64_t local_keys = 0;
            auto end_time = start + std::chrono::seconds(TEST_DURATION);
            
            while (std::chrono::steady_clock::now() < end_time) {
                for (size_t j = 0; j < TEST_BATCH; ++j) {
                    randombytes_buf(&buffers.seeds[j * 32], 32);
                    crypto_sign_ed25519_keypair(&buffers.pubkeys[j * 32], &buffers.privkeys[j * 64]);
                }
                local_keys += TEST_BATCH;
            }
            
            total_keys.fetch_add(local_keys);
        };
        
        threads.emplace_back(test_worker);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    double keys_per_sec = total_keys.load() / elapsed.count();
    
    std::cout << "Xeon Gold 5220 Performance: " << std::fixed << std::setprecision(0) 
              << keys_per_sec << " keys/sec (" << test_threads << " test threads)" << std::endl;
    
    return keys_per_sec;
}

// Main function
int main(int argc, char* argv[]) {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    // Check AVX-512 support
    bool avx512_supported = false;
    #ifdef __AVX512F__
    avx512_supported = true;
    #endif
    
    // Check NUMA support
    bool numa_supported = (numa_available() >= 0);
    
    std::cout << "🔍 MCKeySearcher - Xeon Gold 5220 (Cascade Lake) Optimized Ed25519 Key Searcher\n";
    std::cout << "🚀 Optimized for Intel Xeon Gold 5220 (Cascade Lake) with " << (avx512_supported ? "AVX-512" : "AVX2") << "\n";
    std::cout << "🏗️  NUMA support: " << (numa_supported ? "Available" : "Not available") << "\n\n";
    
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
    std::cout << "2. Prefix + Suffix\n";
    std::cout << "Choice (1-2): ";
    std::cin >> config.search_mode;
    
    if (config.search_mode != 1 && config.search_mode != 2) {
        config.search_mode = 1;
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
    
    // Calculate optimal thread distribution for 2-socket system
    unsigned int total_cores = std::thread::hardware_concurrency();
    config.cpu_threads = total_cores; // Use ALL 72 cores
    
    std::cout << "\nXeon Gold 5220 (Cascade Lake) Configuration:\n";
    std::cout << "Total CPU cores: " << total_cores << " (36 per socket)\n";
    std::cout << "CPU threads to use: " << config.cpu_threads << " (all cores)\n";
    std::cout << "NUMA-aware: " << (config.numa_aware && numa_supported ? "Yes" : "No") << " (2 nodes)\n";
    std::cout << "NUMA support: " << (numa_supported ? "Available" : "Not available") << "\n";
    std::cout << "AVX-512: " << (avx512_supported ? "Yes" : "No") << "\n";
    std::cout << "Batch size: " << config.batch_size << " (optimized for Cascade Lake AVX-512)\n\n";
    
    // Measure server performance
    double keys_per_sec = measure_server_performance(config);
    
    // Calculate expected time
    size_t prefix_len = prefix.length() / 2;
    double combinations = pow(16.0, prefix_len);
    double expected_time = combinations / keys_per_sec;
    
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
    
    // Start server-optimized search
    std::cout << "\nStarting Xeon Gold 5220 (Cascade Lake) optimized search...\n";
    std::cout << "Found keys will be saved to found_keys.txt\n";
    if (numa_supported) {
        std::cout << "Note: Some 'mbind: Invalid argument' warnings are normal in VMware environments\n";
        std::cout << "The program will continue to work optimally despite these warnings\n\n";
    } else {
        std::cout << "Note: Running without NUMA optimization (normal in some VM environments)\n\n";
    }
    
    std::vector<std::thread> threads;
    
    // Start CPU workers with optimal distribution across both sockets
    for (int i = 0; i < config.cpu_threads; ++i) {
        threads.emplace_back(server_cpu_worker, std::ref(config), i, i);
        std::cout << "Started CPU worker " << i << " on core " << i << " (NUMA " << get_numa_node(i) << ")\n";
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
        double current_keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        print_status(current_attempts, current_found, current_keys_per_sec, "XEON-GOLD");
        
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

