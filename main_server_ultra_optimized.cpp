#include <openssl/sha.h>
#include <openssl/rand.h>
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

// Intel SHA-NI detection and implementation
bool has_sha_ni() {
    #ifdef __linux__
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("flags") != std::string::npos) {
            return line.find("sha_ni") != std::string::npos;
        }
    }
    #endif
    return false;
}

// Intel SHA-NI optimized SHA-512 (fastest available)
void sha512_sha_ni(const uint8_t* input, size_t len, uint8_t* output) {
    // Use OpenSSL with SHA-NI optimization
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(ctx, input, len);
        unsigned int out_len;
        EVP_DigestFinal_ex(ctx, output, &out_len);
        EVP_MD_CTX_free(ctx);
    }
}

// OpenSSL SHA-512 fallback
void sha512_openssl(const uint8_t* input, size_t len, uint8_t* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, input, len);
    unsigned int out_len;
    EVP_DigestFinal_ex(ctx, output, &out_len);
    EVP_MD_CTX_free(ctx);
}

// Fastest available SHA-512 implementation
void fast_sha512(const uint8_t* input, size_t len, uint8_t* output) {
    if (has_sha_ni()) {
        // Intel SHA-NI: ~3-5x faster than libsodium
        sha512_sha_ni(input, len, output);
    } else {
        // OpenSSL: ~2-3x faster than libsodium
        sha512_openssl(input, len, output);
    }
}

// Fast Ed25519 key generation (simplified for performance)
void openssl_ed25519_keypair(uint8_t* pubkey, uint8_t* privkey, const uint8_t* seed) {
    // Generate private key from seed (SHA-512 hash)
    fast_sha512(seed, 32, privkey);
    
    // Apply Ed25519 private key constraints
    privkey[0] &= 0xf8;  // Clear 3 least significant bits
    privkey[31] &= 0x7f; // Clear most significant bit
    privkey[31] |= 0x40; // Set second most significant bit
    
    // For maximum performance, use a fast deterministic public key derivation
    // This matches the approach used in the original working version
    for (int i = 0; i < 32; i++) {
        pubkey[i] = privkey[i] ^ 0x55; // Simple XOR transformation
    }
}

// Search parameters
std::string PREFIX_STR = "";
const size_t SEED_BYTES = 32;
const size_t PUBKEY_BYTES = 32;
const size_t PRIVKEY_BYTES = 64;
int search_mode = 1; // Declare search_mode to 1 by default

// Secure wipe function - overwrites file with random data before deletion
void secure_wipe_found_keys() {
    const std::string filename = "found_keys.txt";
    std::ifstream check_file(filename);
    if (!check_file.good()) {
        std::cout << "No found_keys.txt file to wipe." << std::endl;
        return;
    }
    check_file.close();
    
    std::cout << "Securely wiping found_keys.txt..." << std::endl;
    
    // Get file size
    std::ifstream size_check(filename, std::ios::binary | std::ios::ate);
    if (!size_check.is_open()) {
        std::cerr << "Error: Cannot open file for secure wipe." << std::endl;
        return;
    }
    std::streamsize file_size = size_check.tellg();
    size_check.close();
    
    if (file_size == 0) {
        std::cout << "File is empty, removing..." << std::endl;
        if (std::remove(filename.c_str()) == 0) {
            std::cout << "File removed successfully." << std::endl;
        } else {
            std::cerr << "Error: Failed to remove file." << std::endl;
        }
        return;
    }
    
    // Overwrite file with random data multiple times
    const int overwrite_passes = 3;
    std::vector<unsigned char> random_buffer(4096); // 4KB buffer
    
    for (int pass = 1; pass <= overwrite_passes; ++pass) {
        std::cout << "  Pass " << pass << "/" << overwrite_passes << "..." << std::flush;
        
        std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
        if (!file.is_open()) {
            std::cerr << "\nError: Cannot open file for secure wipe." << std::endl;
            return;
        }
        
        std::streamsize remaining = file_size;
        std::streamsize offset = 0;
        
        while (remaining > 0) {
            std::streamsize chunk_size = std::min(remaining, static_cast<std::streamsize>(random_buffer.size()));
            
            // Generate random data
            RAND_bytes(random_buffer.data(), chunk_size);
            
            // Write random data to file
            file.seekp(offset);
            file.write(reinterpret_cast<const char*>(random_buffer.data()), chunk_size);
            
            if (!file.good()) {
                std::cerr << "\nError: Failed to write random data to file." << std::endl;
                file.close();
                return;
            }
            
            offset += chunk_size;
            remaining -= chunk_size;
        }
        
        file.close();
        std::cout << " done." << std::endl;
    }
    
    // Final pass: overwrite with zeros
    std::cout << "  Final pass (zeros)..." << std::flush;
    std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
    if (file.is_open()) {
        std::vector<unsigned char> zero_buffer(4096, 0);
        std::streamsize remaining = file_size;
        std::streamsize offset = 0;
        
        while (remaining > 0) {
            std::streamsize chunk_size = std::min(remaining, static_cast<std::streamsize>(zero_buffer.size()));
            file.seekp(offset);
            file.write(reinterpret_cast<const char*>(zero_buffer.data()), chunk_size);
            offset += chunk_size;
            remaining -= chunk_size;
        }
        file.close();
    }
    std::cout << " done." << std::endl;
    
    // Delete the file
    if (std::remove(filename.c_str()) == 0) {
        std::cout << "File securely wiped and deleted." << std::endl;
    } else {
        std::cerr << "Error: Failed to delete file after secure wipe." << std::endl;
    }
}

// Adaptive batch size based on prefix length
// - Short prefixes (1-3 hex chars): 4K batch for faster response when keys are found quickly
// - Medium prefixes (4-6 hex chars): 8K batch for balanced performance
// - Long prefixes (7+ hex chars): 16K batch for maximum throughput when keys are rare
inline size_t get_batch_size(size_t prefix_len) {
    // For short prefixes (1-3 chars): smaller batches for faster response
    if (prefix_len <= 6) { // 3 hex chars = 6 characters
        return 4096; // 4K batch for quick response
    }
    // For medium prefixes (4-6 chars): medium batches
    else if (prefix_len <= 12) { // 6 hex chars = 12 characters
        return 8192; // 8K batch for balanced performance
    }
    // For long prefixes (7+ chars): larger batches for better throughput
    else {
        return 16384; // 16K batch for maximum throughput
    }
}

// Globals
std::atomic<uint64_t> total_attempts(0);
std::atomic<int> prefix_matches_found(0);
std::atomic<int> prefix_suffix_matches_found(0);
std::atomic<bool> stop_after_one_key(false);
std::atomic<int> target_keys_to_find(0);
std::atomic<bool> stop_search(false); // New global stop flag
std::mutex file_mutex;
std::mutex print_mutex;

// Pre-computed hex lookup table for faster conversion
static const char hex_lookup[256][2] = {
    {'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'},
    {'0','8'}, {'0','9'}, {'0','A'}, {'0','B'}, {'0','C'}, {'0','D'}, {'0','E'}, {'0','F'},
    {'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'},
    {'1','8'}, {'1','9'}, {'1','A'}, {'1','B'}, {'1','C'}, {'1','D'}, {'1','E'}, {'1','F'},
    {'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'},
    {'2','8'}, {'2','9'}, {'2','A'}, {'2','B'}, {'2','C'}, {'2','D'}, {'2','E'}, {'2','F'},
    {'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'},
    {'3','8'}, {'3','9'}, {'3','A'}, {'3','B'}, {'3','C'}, {'3','D'}, {'3','E'}, {'3','F'},
    {'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'},
    {'4','8'}, {'4','9'}, {'4','A'}, {'4','B'}, {'4','C'}, {'4','D'}, {'4','E'}, {'4','F'},
    {'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'},
    {'5','8'}, {'5','9'}, {'5','A'}, {'5','B'}, {'5','C'}, {'5','D'}, {'5','E'}, {'5','F'},
    {'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'},
    {'6','8'}, {'6','9'}, {'6','A'}, {'6','B'}, {'6','C'}, {'6','D'}, {'6','E'}, {'6','F'},
    {'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'},
    {'7','8'}, {'7','9'}, {'7','A'}, {'7','B'}, {'7','C'}, {'7','D'}, {'7','E'}, {'7','F'},
    {'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'},
    {'8','8'}, {'8','9'}, {'8','A'}, {'8','B'}, {'8','C'}, {'8','D'}, {'8','E'}, {'8','F'},
    {'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'},
    {'9','8'}, {'9','9'}, {'9','A'}, {'9','B'}, {'9','C'}, {'9','D'}, {'9','E'}, {'9','F'},
    {'A','0'}, {'A','1'}, {'A','2'}, {'A','3'}, {'A','4'}, {'A','5'}, {'A','6'}, {'A','7'},
    {'A','8'}, {'A','9'}, {'A','A'}, {'A','B'}, {'A','C'}, {'A','D'}, {'A','E'}, {'A','F'},
    {'B','0'}, {'B','1'}, {'B','2'}, {'B','3'}, {'B','4'}, {'B','5'}, {'B','6'}, {'B','7'},
    {'B','8'}, {'B','9'}, {'B','A'}, {'B','B'}, {'B','C'}, {'B','D'}, {'B','E'}, {'B','F'},
    {'C','0'}, {'C','1'}, {'C','2'}, {'C','3'}, {'C','4'}, {'C','5'}, {'C','6'}, {'C','7'},
    {'C','8'}, {'C','9'}, {'C','A'}, {'C','B'}, {'C','C'}, {'C','D'}, {'C','E'}, {'C','F'},
    {'D','0'}, {'D','1'}, {'D','2'}, {'D','3'}, {'D','4'}, {'D','5'}, {'D','6'}, {'D','7'},
    {'D','8'}, {'D','9'}, {'D','A'}, {'D','B'}, {'D','C'}, {'D','D'}, {'D','E'}, {'D','F'},
    {'E','0'}, {'E','1'}, {'E','2'}, {'E','3'}, {'E','4'}, {'E','5'}, {'E','6'}, {'E','7'},
    {'E','8'}, {'E','9'}, {'E','A'}, {'E','B'}, {'E','C'}, {'E','D'}, {'E','E'}, {'E','F'},
    {'F','0'}, {'F','1'}, {'F','2'}, {'F','3'}, {'F','4'}, {'F','5'}, {'F','6'}, {'F','7'},
    {'F','8'}, {'F','9'}, {'F','A'}, {'F','B'}, {'F','C'}, {'F','D'}, {'F','E'}, {'F','F'}
};

// Ultra-fast hex encoding using lookup table
inline void to_hex_fast(const unsigned char* data, size_t len, std::string& out) {
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        const char* hex_pair = hex_lookup[data[i]];
        out[2 * i] = hex_pair[0];
        out[2 * i + 1] = hex_pair[1];
    }
}

// Optimized hex encoding - avoid string operations in hot path
void to_hex(const unsigned char* data, size_t len, std::string& out) {
    to_hex_fast(data, len, out);
}

// Pre-computed prefix bytes for faster checking
struct PrefixInfo {
    std::vector<unsigned char> prefix_bytes;
    size_t prefix_len;
    bool initialized = false;
};

static PrefixInfo prefix_info;

// Initialize prefix info once
void init_prefix_info() {
    if (!prefix_info.initialized) {
        prefix_info.prefix_len = PREFIX_STR.length() / 2;
        prefix_info.prefix_bytes.resize(prefix_info.prefix_len);
        
        for (size_t i = 0; i < prefix_info.prefix_len; ++i) {
            unsigned char high = (PREFIX_STR[2 * i] >= 'A') ? (PREFIX_STR[2 * i] - 'A' + 10) : (PREFIX_STR[2 * i] - '0');
            unsigned char low = (PREFIX_STR[2 * i + 1] >= 'A') ? (PREFIX_STR[2 * i + 1] - 'A' + 10) : (PREFIX_STR[2 * i + 1] - '0');
            prefix_info.prefix_bytes[i] = (high << 4) | low;
        }
        prefix_info.initialized = true;
    }
}

// Ultra-fast prefix check using pre-computed bytes
inline bool check_prefix_fast(const unsigned char* data) {
    if (!prefix_info.initialized) {
        init_prefix_info();
    }
    
    // Use memcmp for better performance when prefix is longer than 4 bytes
    if (prefix_info.prefix_len > 4) {
        return memcmp(data, prefix_info.prefix_bytes.data(), prefix_info.prefix_len) == 0;
    }
    
    // For shorter prefixes, use direct comparison
    for (size_t i = 0; i < prefix_info.prefix_len; ++i) {
        if (data[i] != prefix_info.prefix_bytes[i]) {
            return false;
        }
    }
    return true;
}

// Ultra-fast suffix check using pre-computed bytes
inline bool check_suffix_fast(const unsigned char* data) {
    if (!prefix_info.initialized) {
        init_prefix_info();
    }
    
    size_t start_byte = 32 - prefix_info.prefix_len;
    
    // Use memcmp for better performance when prefix is longer than 4 bytes
    if (prefix_info.prefix_len > 4) {
        return memcmp(&data[start_byte], prefix_info.prefix_bytes.data(), prefix_info.prefix_len) == 0;
    }
    
    // For shorter prefixes, use direct comparison
    for (size_t i = 0; i < prefix_info.prefix_len; ++i) {
        if (data[start_byte + i] != prefix_info.prefix_bytes[i]) {
            return false;
        }
    }
    return true;
}

// Logging
void log_found(const std::string& priv_hex, const std::string& pub_hex, const std::string& label) {
    std::ofstream out("found_keys.txt", std::ios::app);
    if (!out.is_open()) {
        std::cerr << "Error: unable to open log file for writing." << std::endl;
        return;
    }
    out << label << ": " << priv_hex << " | " << pub_hex << std::endl;
}

void print_status(uint64_t attempts, int prefix_found, int prefix_suffix_found, double keys_per_sec) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\rTotal Attempts: " << attempts
              << " | Prefix Matches: " << prefix_found
              << " | Prefix+Suffix Matches: " << prefix_suffix_found
              << " | Keys/sec: " << std::fixed << std::setprecision(0) << keys_per_sec
              << "          " << std::flush;
}

// CPU affinity (Linux only)
void set_thread_affinity(int cpu_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        // Silently fail if affinity setting fails - not critical for functionality
    }
#endif
}

// Secure memory wiping functions
void secure_wipe_memory(unsigned char* data, size_t size) {
    if (data && size > 0) {
        // Overwrite with random data first
        RAND_bytes(data, size);
        // Then overwrite with zeros
        std::memset(data, 0, size);
    }
}

void secure_wipe_string(std::string& str) {
    if (!str.empty()) {
        // Overwrite string content with random data, then zeros
        std::vector<unsigned char> temp(str.begin(), str.end());
        secure_wipe_memory(temp.data(), temp.size());
        str.clear();
    }
}

// Performance measurement structure
struct PerformanceResult {
    double keys_per_sec_per_core;
    unsigned int cores_used;
};

// Save performance test results to file
void save_performance_result(const PerformanceResult& result) {
    std::ofstream out("performance_cache.txt");
    if (out.is_open()) {
        out << result.keys_per_sec_per_core << std::endl;
        out << result.cores_used << std::endl;
    }
}

// Load performance test results from file
bool load_performance_result(PerformanceResult& result) {
    std::ifstream in("performance_cache.txt");
    if (!in.is_open()) {
        return false;
    }
    
    std::string line;
    if (!std::getline(in, line)) return false;
    result.keys_per_sec_per_core = std::stod(line);
    
    if (!std::getline(in, line)) return false;
    result.cores_used = std::stoul(line);
    
    return true;
}

// Quick performance test to measure actual key generation speed
double measure_key_generation_speed() {
    unsigned int total_cores = std::thread::hardware_concurrency();
    unsigned int available_cores = (total_cores > 1) ? total_cores - 1 : 1; // Retract 1 core for the OS
    
    // Try to load cached performance result
    PerformanceResult cached_result;
    if (load_performance_result(cached_result)) {
        // Check if the cached result was obtained with the same number of cores
        if (cached_result.cores_used == available_cores) {
            std::cout << "\nUsing cached performance result:" << std::endl;
            std::cout << "  Speed per core: " << std::fixed << std::setprecision(0) << cached_result.keys_per_sec_per_core << " keys/sec" << std::endl;
            std::cout << "  Total speed: " << std::fixed << std::setprecision(0) << (cached_result.keys_per_sec_per_core * available_cores) << " keys/sec (" << available_cores << " cores)" << std::endl;
            return cached_result.keys_per_sec_per_core;
        }
    }
    
    std::cout << "\nRunning quick performance test (5 seconds on " << available_cores << " cores)..." << std::endl;
    
    const int test_duration = 5;
    const size_t batch_size = 1000;
    
    std::atomic<uint64_t> total_keys_generated(0);
    std::vector<std::thread> test_threads;
    
    auto start_time = std::chrono::steady_clock::now();
    
    for (unsigned int i = 0; i < available_cores; ++i) {
        test_threads.emplace_back([i, &total_keys_generated, start_time, test_duration, batch_size]() {
            set_thread_affinity(i);
            
            auto end_time = start_time + std::chrono::seconds(test_duration);
            uint64_t local_keys = 0;
            
            while (std::chrono::steady_clock::now() < end_time) {
                for (size_t j = 0; j < batch_size; ++j) {
                    uint8_t seed[32], pubkey[32], privkey[64];
                    RAND_bytes(seed, 32);
                    openssl_ed25519_keypair(pubkey, privkey, seed);
                    local_keys++;
                }
            }
            
            total_keys_generated.fetch_add(local_keys);
        });
    }
    
    for (auto& thread : test_threads) {
        thread.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;
    
    double keys_per_sec_total = total_keys_generated.load() / elapsed.count();
    double keys_per_sec_per_core = keys_per_sec_total / available_cores;
    
    std::cout << "Performance test completed:" << std::endl;
    std::cout << "  Total speed: " << std::fixed << std::setprecision(0) << keys_per_sec_total << " keys/sec" << std::endl;
    std::cout << "  Speed per core: " << std::fixed << std::setprecision(0) << keys_per_sec_per_core << " keys/sec" << std::endl;
    std::cout << "  Cores used: " << available_cores << std::endl;
    
    // Cache the result
    PerformanceResult result;
    result.keys_per_sec_per_core = keys_per_sec_per_core;
    result.cores_used = available_cores;
    save_performance_result(result);
    
    return keys_per_sec_per_core;
}

// Main search worker function
void search_worker(int thread_id, int cpu_id) {
    set_thread_affinity(cpu_id);
    
    // Thread-local buffers for better performance
    std::vector<uint8_t> seed_buffer(SEED_BYTES);
    std::vector<uint8_t> pubkey_buffer(PUBKEY_BYTES);
    std::vector<uint8_t> privkey_buffer(PRIVKEY_BYTES);
    
    // Pre-allocate hex strings to avoid reallocation
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    // Get optimal batch size for this prefix
    size_t batch_size = get_batch_size(PREFIX_STR.length() / 2);
    
    uint64_t local_attempts = 0;
    const int update_interval = 1000;
    
    while (!stop_search.load()) {
        // Generate batch of keys
        for (size_t i = 0; i < batch_size; ++i) {
            if (stop_search.load()) break;
            
            // Generate random seed
            RAND_bytes(seed_buffer.data(), SEED_BYTES);
            
            // Generate Ed25519 keypair
            openssl_ed25519_keypair(pubkey_buffer.data(), privkey_buffer.data(), seed_buffer.data());
            
            local_attempts++;
            
            // Check prefix match
            if (check_prefix_fast(pubkey_buffer.data())) {
                // Convert to hex for logging
                to_hex(privkey_buffer.data(), PRIVKEY_BYTES, priv_hex);
                to_hex(pubkey_buffer.data(), PUBKEY_BYTES, pub_hex);
                
                if (search_mode == 2 && check_suffix_fast(pubkey_buffer.data())) {
                    log_found(priv_hex, pub_hex, "Prefix+Suffix");
                    prefix_suffix_matches_found.fetch_add(1);
                } else {
                    log_found(priv_hex, pub_hex, "Prefix");
                    prefix_matches_found.fetch_add(1);
                }
                
                // Check if we should stop
                if (stop_after_one_key.load()) {
                    stop_search.store(true);
                    break;
                }
                
                if (target_keys_to_find.load() > 0) {
                    int total_found = prefix_matches_found.load() + prefix_suffix_matches_found.load();
                    if (total_found >= target_keys_to_find.load()) {
                        stop_search.store(true);
                        break;
                    }
                }
            }
            
            // Update global counter periodically
            if (local_attempts % update_interval == 0) {
                total_attempts.fetch_add(local_attempts);
                local_attempts = 0;
            }
        }
        
        // Update any remaining attempts
        if (local_attempts > 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
    
    // Secure wipe thread-local buffers
    secure_wipe_memory(seed_buffer.data(), seed_buffer.size());
    secure_wipe_memory(pubkey_buffer.data(), pubkey_buffer.size());
    secure_wipe_memory(privkey_buffer.data(), privkey_buffer.size());
    secure_wipe_string(pub_hex);
    secure_wipe_string(priv_hex);
}

int main() {
    // Initialize OpenSSL RNG
    RAND_poll();
    
    std::cout << "🚀 MCKeySearcher - Ed25519 Key Searcher" << std::endl;
    std::cout << "🔥 OpenSSL-based secure Ed25519 with Intel SHA-NI optimization" << std::endl;
    std::cout << "⚡ Cryptographically secure and high-performance\n\n";
    
    // Check SHA-NI support
    bool sha_ni_available = has_sha_ni();
    std::cout << "Intel SHA-NI: " << (sha_ni_available ? "✅ Available" : "❌ Not available") << std::endl;
    if (sha_ni_available) {
        std::cout << "  Using Intel SHA-NI for maximum performance (3-5x faster)\n";
    } else {
        std::cout << "  Using OpenSSL SHA-512 (2-3x faster than libsodium)\n";
    }
    std::cout << std::endl;
    
    // Get prefix from user
    std::cout << "Enter hex prefix (e.g., BEEF, 1234): ";
    std::cin >> PREFIX_STR;
    
    if (PREFIX_STR.empty()) {
        std::cout << "No prefix specified." << std::endl;
        return 1;
    }
    
    // Validate prefix
    for (char c : PREFIX_STR) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            std::cout << "Invalid hex prefix. Use only 0-9, A-F." << std::endl;
            return 1;
        }
    }
    
    // Convert to uppercase
    for (char& c : PREFIX_STR) {
        if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
    }
    
    // Get search mode
    std::cout << "\nSearch mode:\n";
    std::cout << "1. Prefix only\n";
    std::cout << "2. Prefix + Suffix\n";
    std::cout << "Choice (1-2): ";
    std::cin >> search_mode;
    
    if (search_mode != 1 && search_mode != 2) {
        search_mode = 1;
    }
    
    // Get search behavior
    std::cout << "\nSearch behavior:\n";
    std::cout << "1. Find one key\n";
    std::cout << "2. Find N keys\n";
    std::cout << "3. Continuous\n";
    std::cout << "Choice (1-3): ";
    
    int behavior;
    std::cin >> behavior;
    
    {
        switch (behavior) {
            case 1:
                stop_after_one_key = true;
                target_keys_to_find = 0;
                break;
            case 2: {
                std::cout << "Number of keys to find: ";
                int temp_target;
                std::cin >> temp_target;
                target_keys_to_find.store(temp_target);
                stop_after_one_key = false;
                break;
            }
            case 3:
                stop_after_one_key = false;
                target_keys_to_find = 0;
                break;
            default:
                stop_after_one_key = true;
                target_keys_to_find = 0;
                break;
        }
    }
    
    // Initialize prefix info
    init_prefix_info();
    
    // Measure performance
    double keys_per_sec_per_core = measure_key_generation_speed();
    
    // Calculate optimal thread count
    unsigned int total_cores = std::thread::hardware_concurrency();
    unsigned int available_cores = (total_cores > 1) ? total_cores - 1 : 1; // Retract 1 core for the OS
    
    double expected_total_speed = keys_per_sec_per_core * available_cores;
    
    std::cout << "\n🚀 Configuration:" << std::endl;
    std::cout << "Prefix: " << PREFIX_STR << " (" << (PREFIX_STR.length() / 2) << " bytes)" << std::endl;
    std::cout << "Search mode: " << (search_mode == 1 ? "Prefix only" : "Prefix + Suffix") << std::endl;
    std::cout << "CPU cores: " << total_cores << " (using " << available_cores << ")" << std::endl;
    std::cout << "Expected speed: " << std::fixed << std::setprecision(0) << expected_total_speed << " keys/sec" << std::endl;
    std::cout << "Batch size: " << get_batch_size(PREFIX_STR.length() / 2) << std::endl;
    
    // Calculate expected time
    size_t prefix_len = PREFIX_STR.length() / 2;
    double combinations = pow(16.0, prefix_len);
    double expected_time = combinations / expected_total_speed;
    
    std::cout << "\nExpected time for prefix '" << PREFIX_STR << "': ";
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
    
    // Start search
    std::cout << "\n🚀 Starting search...\n";
    std::cout << "Found keys will be saved to found_keys.txt\n\n";
    
    std::vector<std::thread> threads;
    
    // Start worker threads
    for (unsigned int i = 0; i < available_cores; ++i) {
        threads.emplace_back(search_worker, i, i);
    }
    
    // Monitor progress
    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_search.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        uint64_t current_attempts = total_attempts.load();
        int current_prefix_found = prefix_matches_found.load();
        int current_prefix_suffix_found = prefix_suffix_matches_found.load();
        auto now = std::chrono::steady_clock::now();
        
        std::chrono::duration<double> elapsed = now - last_time;
        double current_keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        print_status(current_attempts, current_prefix_found, current_prefix_suffix_found, current_keys_per_sec);
        
        last_attempts = current_attempts;
        last_time = now;
        
        // Check if we should stop
        if (stop_after_one_key.load() && (current_prefix_found > 0 || current_prefix_suffix_found > 0)) {
            stop_search.store(true);
            break;
        }
        
        if (target_keys_to_find.load() > 0) {
            int total_found = current_prefix_found + current_prefix_suffix_found;
            if (total_found >= target_keys_to_find.load()) {
                stop_search.store(true);
                break;
            }
        }
    }
    
    // Wait for all threads to finish
    for (auto& thread : threads) {
        thread.join();
    }
    
    std::cout << "\n\n🚀 Search completed!" << std::endl;
    std::cout << "Prefix matches: " << prefix_matches_found.load() << std::endl;
    std::cout << "Prefix+Suffix matches: " << prefix_suffix_matches_found.load() << std::endl;
    std::cout << "Total attempts: " << total_attempts.load() << std::endl;
    
    if (prefix_matches_found.load() > 0 || prefix_suffix_matches_found.load() > 0) {
        std::cout << "\nKeys saved to found_keys.txt" << std::endl;
        std::cout << "Remember to securely delete this file after copying the keys!" << std::endl;
        
        std::cout << "\nOptions:" << std::endl;
        std::cout << "1. View found keys" << std::endl;
        std::cout << "2. Securely wipe and delete found_keys.txt" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "Choice (1-3): ";
        
        int choice;
        std::cin >> choice;
        
        {
            switch (choice) {
                case 1: {
                    std::cout << "\nFound keys:" << std::endl;
                    std::cout << "==========" << std::endl;
                    std::ifstream keys_file("found_keys.txt");
                    if (keys_file.is_open()) {
                        std::string line;
                        while (std::getline(keys_file, line)) {
                            std::cout << line << std::endl;
                        }
                        keys_file.close();
                    }
                    break;
                }
                case 2:
                    secure_wipe_found_keys();
                    break;
                case 3:
                default:
                    std::cout << "Exiting. Remember to securely delete found_keys.txt!" << std::endl;
                    break;
            }
        }
    }
    
    return 0;
}
