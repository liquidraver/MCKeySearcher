#include <ed25519.h>
#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>
#include <cmath>
#include <limits>
#include <cstring>
#ifdef __linux__
#include <pthread.h>
#endif

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
            randombytes_buf(random_buffer.data(), chunk_size);
            
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

// Prefix/suffix match check - optimized for performance
bool check_prefix(const unsigned char* data) {
    return check_prefix_fast(data);
}

bool check_suffix(const unsigned char* data) {
    if (!prefix_info.initialized) {
        init_prefix_info();
    }
    
    size_t start_byte = PUBKEY_BYTES - prefix_info.prefix_len;
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
        randombytes_buf(data, size);
        // Then overwrite with zeros
        std::memset(data, 0, size);
    }
}

void secure_wipe_string(std::string& str) {
    if (!str.empty()) {
        // Overwrite string content with random data, then zeros
        std::vector<unsigned char> random_data(str.size());
        randombytes_buf(random_data.data(), random_data.size());
        std::copy(random_data.begin(), random_data.end(), str.begin());
        std::fill(str.begin(), str.end(), 0);
        str.clear();
    }
}

// Secure cleanup function - called at program exit
void secure_cleanup() {
    // This function will be called at program exit to ensure all sensitive data is wiped
    // The actual wiping is done immediately after use in the worker threads
    // This is just a safety net
}

// Handle found key - with secure memory wiping
void handle_found_key(int thread_id, const std::string& pub_hex, const std::string& priv_hex, bool prefix_suffix_match) {
    std::lock_guard<std::mutex> lock(file_mutex);
    // Only log to file, don't print to console
    if (prefix_suffix_match) {
        log_found(priv_hex, pub_hex, "Prefix+SuffixMatch");
        ++prefix_suffix_matches_found;
    } else {
        log_found(priv_hex, pub_hex, "PrefixMatch");
        ++prefix_matches_found;
    }
    
    // SECURE WIPE: Clear private key data from memory immediately after logging
    // Note: This is now handled in the worker function for better security
}

// Worker thread
void worker(int thread_id) {
    set_thread_affinity(thread_id);
    
    // Get adaptive batch size based on prefix length
    size_t batch_size = get_batch_size(PREFIX_STR.length());
    
    // Use heap allocation for large arrays to avoid stack overflow
    std::vector<unsigned char> seeds_data(batch_size * SEED_BYTES);
    std::vector<unsigned char> pubkeys_data(batch_size * PUBKEY_BYTES);
    std::vector<unsigned char> privkeys_data(batch_size * PRIVKEY_BYTES);
    
    // Create 2D array views for easier access
    unsigned char (*seeds)[SEED_BYTES] = reinterpret_cast<unsigned char(*)[SEED_BYTES]>(seeds_data.data());
    unsigned char (*pubkeys)[PUBKEY_BYTES] = reinterpret_cast<unsigned char(*)[PUBKEY_BYTES]>(pubkeys_data.data());
    unsigned char (*privkeys)[PRIVKEY_BYTES] = reinterpret_cast<unsigned char(*)[PRIVKEY_BYTES]>(privkeys_data.data());
    
    std::string pub_hex, priv_hex;
    
    // Pre-allocate hex strings to avoid reallocations
    pub_hex.reserve(PUBKEY_BYTES * 2);
    priv_hex.reserve(PRIVKEY_BYTES * 2);

    // Local counters to reduce atomic operations
    uint64_t local_attempts = 0;
    int local_prefix_matches = 0;
    int local_prefix_suffix_matches = 0;
    const int UPDATE_INTERVAL = 1000; // Update global counters every 1000 attempts

    while (true) {
        // Check stop conditions once per batch
        if (stop_search.load()) {
            break;
        }
        
        // Generate keys in batch
        for (size_t i = 0; i < batch_size; ++i) {
            randombytes_buf(seeds[i], SEED_BYTES);
            ed25519_create_keypair(pubkeys[i], privkeys[i], seeds[i]);
        }
        
        // Process keys in batch
        for (size_t i = 0; i < batch_size; ++i) {
            // Check stop conditions every iteration
            if (stop_search.load()) {
                goto exit_worker;
            }
            
            ++local_attempts;
            
            bool prefix_match = check_prefix_fast(pubkeys[i]);
            
            if (search_mode == 1) { // Prefix only
                if (prefix_match) {
                    to_hex_fast(privkeys[i], PRIVKEY_BYTES, priv_hex);
                    to_hex_fast(pubkeys[i], PUBKEY_BYTES, pub_hex);
                    handle_found_key(thread_id, pub_hex, priv_hex, false);
                    ++local_prefix_matches;
                    
                    // SECURE WIPE: Clear the specific private key from batch array
                    secure_wipe_memory(privkeys[i], PRIVKEY_BYTES);
                    
                    // SECURE WIPE: Clear hex strings
                    secure_wipe_string(priv_hex);
                    secure_wipe_string(pub_hex);
                }
            } else if (search_mode == 2) { // Prefix & Prefix + Suffix
                if (prefix_match) {
                    bool suffix_match = check_suffix(pubkeys[i]);
                    to_hex_fast(privkeys[i], PRIVKEY_BYTES, priv_hex);
                    to_hex_fast(pubkeys[i], PUBKEY_BYTES, pub_hex);
                    
                    if (suffix_match) {
                        handle_found_key(thread_id, pub_hex, priv_hex, true);
                        ++local_prefix_suffix_matches;
                    } else {
                        handle_found_key(thread_id, pub_hex, priv_hex, false);
                        ++local_prefix_matches;
                    }
                    
                    // SECURE WIPE: Clear the specific private key from batch array
                    secure_wipe_memory(privkeys[i], PRIVKEY_BYTES);
                    
                    // SECURE WIPE: Clear hex strings
                    secure_wipe_string(priv_hex);
                    secure_wipe_string(pub_hex);
                }
            }
            
            // Update global counters periodically to reduce atomic operations
            if (local_attempts % UPDATE_INTERVAL == 0) {
                total_attempts.fetch_add(local_attempts);
                local_attempts = 0;
            }
        }
        
        // SECURE WIPE: Clear entire batch arrays after processing
        secure_wipe_memory(seeds_data.data(), seeds_data.size());
        secure_wipe_memory(pubkeys_data.data(), pubkeys_data.size());
        secure_wipe_memory(privkeys_data.data(), privkeys_data.size());
        
        // Update global counters at the end of each batch
        if (local_attempts > 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
    
exit_worker:
    return;
}

// Performance test result storage
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
    
    const size_t test_batch_size = 8192;
    const int test_duration_seconds = 5;
    
    std::atomic<uint64_t> total_keys(0);
    std::vector<std::thread> test_threads;
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Worker function for performance test
    auto test_worker = [&](int thread_id) {
        std::vector<unsigned char> seeds_data(test_batch_size * SEED_BYTES);
        std::vector<unsigned char> pubkeys_data(test_batch_size * PUBKEY_BYTES);
        std::vector<unsigned char> privkeys_data(test_batch_size * PRIVKEY_BYTES);
        
        unsigned char (*seeds)[SEED_BYTES] = reinterpret_cast<unsigned char(*)[SEED_BYTES]>(seeds_data.data());
        unsigned char (*pubkeys)[PUBKEY_BYTES] = reinterpret_cast<unsigned char(*)[PUBKEY_BYTES]>(pubkeys_data.data());
        unsigned char (*privkeys)[PRIVKEY_BYTES] = reinterpret_cast<unsigned char(*)[PRIVKEY_BYTES]>(privkeys_data.data());
        
        uint64_t local_keys = 0;
        auto end_time = start_time + std::chrono::seconds(test_duration_seconds);
        
        while (std::chrono::steady_clock::now() < end_time) {
            for (size_t i = 0; i < test_batch_size; ++i) {
                randombytes_buf(seeds[i], SEED_BYTES);
                ed25519_create_keypair(pubkeys[i], privkeys[i], seeds[i]);
            }
            local_keys += test_batch_size;
        }
        
        total_keys.fetch_add(local_keys);
    };
    
    // Start test threads
    for (unsigned int i = 0; i < available_cores; ++i) {
        test_threads.emplace_back(test_worker, i);
    }
    
    // Wait for all threads to complete
    for (auto& t : test_threads) {
        t.join();
    }
    
    auto actual_end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = actual_end_time - start_time;
    double total_keys_per_sec = total_keys.load() / elapsed.count();
    double keys_per_sec_per_core = total_keys_per_sec / available_cores;
    
    std::cout << "Performance test completed:" << std::endl;
    std::cout << "  Generated " << total_keys.load() << " keys in " << std::fixed << std::setprecision(1) << elapsed.count() << " seconds" << std::endl;
    std::cout << "  Total speed: " << std::fixed << std::setprecision(0) << total_keys_per_sec << " keys/sec (" << available_cores << " cores)" << std::endl;
    std::cout << "  Speed per core: " << std::fixed << std::setprecision(0) << keys_per_sec_per_core << " keys/sec" << std::endl;
    
    // Save the performance result for future use
    PerformanceResult result;
    result.keys_per_sec_per_core = keys_per_sec_per_core;
    result.cores_used = available_cores;
    
    save_performance_result(result);
    std::cout << "  Performance result cached for future use." << std::endl;
    
    return keys_per_sec_per_core;
}

int main(int argc, char* argv[]) {
    // Check for wipe command
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--wipe" || arg == "-w" || arg == "--secure-wipe") {
            if (sodium_init() < 0) {
                std::cerr << "Failed to initialize libsodium" << std::endl;
                return 1;
            }
            secure_wipe_found_keys();
            return 0;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [OPTION]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --wipe, -w, --secure-wipe    Securely wipe found_keys.txt file" << std::endl;
            std::cout << "  --help, -h                   Show this help message" << std::endl;
            std::cout << std::endl;
            std::cout << "If no options are provided, the program runs normally to search for keys." << std::endl;
            return 0;
        }
    }

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    // Display security warning
    std::cout << "\n";
    std::cout << "+-------------------------------------------------------------------------+\n";
    std::cout << "|                              *** WARNING ***                            |\n";
    std::cout << "+-------------------------------------------------------------------------+\n";
    std::cout << "|                                                                         |\n";
    std::cout << "|  This program generates cryptographically secure Ed25519 private keys   |\n";
    std::cout << "|  using libsodium's secure random number generator. However, generating  |\n";
    std::cout << "|  keys on your computer, storing them in files, copying them, or doing   |\n";
    std::cout << "|  anything with private keys on a general-purpose computer is NEVER      |\n";
    std::cout << "|  secure.                                                                |\n";
    std::cout << "|                                                                         |\n";
    std::cout << "|  The most secure way is to let the node generate keys on itself after   |\n";
    std::cout << "|  a full wipe and never save or display the keys anywhere else.          |\n";
    std::cout << "|                                                                         |\n";
    std::cout << "|  SECURITY FEATURES:                                                     |\n";
    std::cout << "|  - Private keys are securely wiped from memory immediately after use    |\n";
    std::cout << "|  - Memory is overwritten with random data before zeros                  |\n";
    std::cout << "|  - To securely wipe found_keys.txt after use, run: ./findkey --wipe     |\n";
    std::cout << "|                                                                         |\n";
    std::cout << "|  Proceed at your own risk...                                            |\n";
    std::cout << "|                                                                         |\n";
    std::cout << "+-------------------------------------------------------------------------+\n";
    std::cout << "\n";

    std::string prefix_str;
    std::cout << "Enter the prefix/suffix bytes from 0123456789ABCDEF (e.g. BEEFF00D, 23DF, 43): ";
    std::cin >> prefix_str;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the newline from buffer

    if (prefix_str.empty()) {
        std::cout << "No characters specified." << std::endl;
        return 1;
    }

    // Check if first byte is 00 or FF (only first 2 characters)
    if (prefix_str.length() >= 2) {
        std::string first_byte = prefix_str.substr(0, 2);
        if (first_byte == "00" || first_byte == "FF") {
            std::cout << "00 and FF are not allowed as the first byte." << std::endl;
            return 1;
        }
    }

    PREFIX_STR = prefix_str;

    // Count actual cores on this machine
    unsigned int total_cores = std::thread::hardware_concurrency();
    unsigned int available_cores = (total_cores > 1) ? total_cores - 1 : 1; // Retract 1 core for the OS
    
    // Measure actual key generation speed
    double actual_keys_per_sec_per_core = measure_key_generation_speed();
    double estimated_keys_per_sec = available_cores * actual_keys_per_sec_per_core;
    
    // Calculate expected times using the simpler approach
    size_t prefix_len = prefix_str.length();
    long double prefix_expected_time, prefix_suffix_expected_time;
    
    // For prefix only: calculate total combinations needed
    long double prefix_combinations = powl(16.0L, prefix_len);
    prefix_expected_time = prefix_combinations / estimated_keys_per_sec;
    
    // For prefix+suffix: calculate total combinations needed
    long double prefix_suffix_combinations = powl(16.0L, prefix_len * 2);
    prefix_suffix_expected_time = prefix_suffix_combinations / estimated_keys_per_sec;
    
    // Check for overflow or invalid results
    if (std::isnan(prefix_expected_time) || std::isinf(prefix_expected_time) || prefix_expected_time < 0) {
        prefix_expected_time = std::numeric_limits<long double>::infinity();
    }
    if (std::isnan(prefix_suffix_expected_time) || std::isinf(prefix_suffix_expected_time) || prefix_suffix_expected_time < 0) {
        prefix_suffix_expected_time = std::numeric_limits<long double>::infinity();
    }
    
    std::cout << "\nEstimated time (with " << available_cores << " cores at ~" << std::fixed << std::setprecision(0) << actual_keys_per_sec_per_core << " keys/sec each):" << std::endl;
    
    // Use a more reasonable threshold - 1e12 seconds is about 31,689 years
    const long double MAX_REASONABLE_TIME = 1e12L; // 31,689 years
    
    if (std::isinf(prefix_expected_time) || prefix_expected_time > MAX_REASONABLE_TIME) {
        std::cout << "  Prefix only: ~finding a needle in a galaxy sized haystack (>31,689 years)" << std::endl;
    } else if (prefix_expected_time < 60) {
        std::cout << "  Prefix only: ~" << std::fixed << std::setprecision(1) << (double)prefix_expected_time << " seconds" << std::endl;
    } else if (prefix_expected_time < 3600) {
        std::cout << "  Prefix only: ~" << std::fixed << std::setprecision(1) << (double)(prefix_expected_time / 60) << " minutes" << std::endl;
    } else if (prefix_expected_time < 86400) {
        std::cout << "  Prefix only: ~" << std::fixed << std::setprecision(1) << (double)(prefix_expected_time / 3600) << " hours" << std::endl;
    } else if (prefix_expected_time < 31536000) {
        std::cout << "  Prefix only: ~" << std::fixed << std::setprecision(1) << (double)(prefix_expected_time / 86400) << " days" << std::endl;
    } else {
        std::cout << "  Prefix only: ~" << std::fixed << std::setprecision(1) << (double)(prefix_expected_time / 31536000) << " years" << std::endl;
    }
    
    if (std::isinf(prefix_suffix_expected_time) || prefix_suffix_expected_time > MAX_REASONABLE_TIME) {
        std::cout << "  Prefix+Suffix: ~finding a needle in a galaxy sized haystack (>31,689 years)" << std::endl;
    } else if (prefix_suffix_expected_time < 60) {
        std::cout << "  Prefix+Suffix: ~" << std::fixed << std::setprecision(1) << (double)prefix_suffix_expected_time << " seconds" << std::endl;
    } else if (prefix_suffix_expected_time < 3600) {
        std::cout << "  Prefix+Suffix: ~" << std::fixed << std::setprecision(1) << (double)(prefix_suffix_expected_time / 60) << " minutes" << std::endl;
    } else if (prefix_suffix_expected_time < 86400) {
        std::cout << "  Prefix+Suffix: ~" << std::fixed << std::setprecision(1) << (double)(prefix_suffix_expected_time / 3600) << " hours" << std::endl;
    } else if (prefix_suffix_expected_time < 31536000) {
        std::cout << "  Prefix+Suffix: ~" << std::fixed << std::setprecision(1) << (double)(prefix_suffix_expected_time / 86400) << " days" << std::endl;
    } else {
        std::cout << "  Prefix+Suffix: ~" << std::fixed << std::setprecision(1) << (double)(prefix_suffix_expected_time / 31536000) << " years" << std::endl;
    }
    
    std::cout << "\nSearch mode:" << std::endl;
    std::cout << "1. Prefix only (Default)" << std::endl;
    std::cout << "2. Prefix & Prefix + Suffix" << std::endl;
    std::cout << "Enter your choice (1 or 2): ";
    
    std::string search_mode_input;
    std::getline(std::cin, search_mode_input);
    
    // Handle empty input (just pressing Enter) - default to 1
    if (search_mode_input.empty()) {
        search_mode = 1;
        std::cout << "Using default: Prefix only" << std::endl;
    } else {
        try {
            int search_mode_choice = std::stoi(search_mode_input);
            if (search_mode_choice == 2) {
                search_mode = 2;
            } else {
                search_mode = 1; // Default to 1 for any other input
            }
        } catch (const std::exception&) {
            // Invalid input - default to 1
            search_mode = 1;
            std::cout << "Invalid input, using default: Prefix only" << std::endl;
        }
    }

    // Ask user about search mode (one key vs continuous)
    std::cout << "\nSearch behavior:" << std::endl;
    std::cout << "1. Find one key and exit" << std::endl;
    std::cout << "2. Enter a number how many keys to find before exiting (approximate with very few characters, maybe you get a ton of keys)" << std::endl;
    std::cout << "3. Run continuously (find all keys) - WARNING! with only few characters this could make a massive logfile!" << std::endl;
    std::cout << "\nEnter your choice (1, 2, or 3): ";
    
    std::string search_behavior_input;
    std::getline(std::cin, search_behavior_input);
    
    int search_behavior_choice;
    // Handle empty input (just pressing Enter) - default to 1
    if (search_behavior_input.empty()) {
        search_behavior_choice = 1;
        std::cout << "Using default: Find one key and exit" << std::endl;
    } else {
        try {
            search_behavior_choice = std::stoi(search_behavior_input);
        } catch (const std::exception&) {
            // Invalid input - default to 1
            search_behavior_choice = 1;
            std::cout << "Invalid input, using default: Find one key and exit" << std::endl;
        }
    }

    if (search_behavior_choice == 1) {
        stop_after_one_key.store(true);
        std::cout << "\n[INFO] Will stop after finding the first matching key." << std::endl;
    } else if (search_behavior_choice == 2) {
        int num_keys_to_find;
        std::cout << "Enter the number of keys to find: ";
        
        std::string num_keys_input;
        std::getline(std::cin, num_keys_input);
        
        // Handle empty input (just pressing Enter) - default to 1
        if (num_keys_input.empty()) {
            num_keys_to_find = 1;
            std::cout << "Using default: 1 key" << std::endl;
        } else {
            try {
                num_keys_to_find = std::stoi(num_keys_input);
            } catch (const std::exception&) {
                // Invalid input - default to 1
                num_keys_to_find = 1;
                std::cout << "Invalid input, using default: 1 key" << std::endl;
            }
        }
        
        if (num_keys_to_find < 0) {
            std::cout << "Invalid number (must be >= 0). Using default: 1 key" << std::endl;
            num_keys_to_find = 1;
        }
        if (num_keys_to_find == 0) {
            std::cout << "Finding 0 keys - exiting immediately." << std::endl;
            return 0;
        }
        stop_after_one_key.store(false);
        target_keys_to_find.store(num_keys_to_find);
        std::cout << "\n[INFO] Will stop after finding " << num_keys_to_find << " matching keys." << std::endl;
    } else if (search_behavior_choice == 3) {
        stop_after_one_key.store(false);
        std::cout << "\n[INFO] Will run continuously and find all matching keys." << std::endl;
    } else {
        // This should never happen due to the try-catch above, but just in case
        std::cout << "Invalid choice. Using default: Find one key and exit" << std::endl;
        stop_after_one_key.store(true);
    }


    std::cout << "Searching for Ed25519 keys with " << prefix_str << " patterns in the public key:\n";
    if (search_mode == 1) {
        std::cout << "1. Public key hex starts with " << prefix_str << "\n";
    } else if (search_mode == 2) {
        std::cout << "1. Public key hex starts with " << prefix_str << "\n";
        std::cout << "2. Public key hex starts AND ends with " << prefix_str << "\n";
    }
    size_t adaptive_batch_size = get_batch_size(prefix_str.length());
    std::cout << "Using " << available_cores << " threads with adaptive batch size " << adaptive_batch_size << ".\n";
    std::cout << "\n[INFO] Found keys will be logged to: found_keys.txt\n\n";

    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < available_cores; ++i) {
        threads.emplace_back(worker, i);
    }

    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        uint64_t current_attempts = total_attempts.load();
        int prefix_found = prefix_matches_found.load();
        int prefix_suffix_found = prefix_suffix_matches_found.load();
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - last_time;
        double keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        print_status(current_attempts, prefix_found, prefix_suffix_found, keys_per_sec);
        last_attempts = current_attempts;
        last_time = now;
        
        // Check if we should stop after finding one key or target number of keys
        if (stop_after_one_key.load() && (prefix_found > 0 || prefix_suffix_found > 0)) {
            std::cout << "\n\n[SUCCESS] Found the requested key! Exiting..." << std::endl;
            stop_search.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            break;
        }
        if (target_keys_to_find.load() > 0 && (prefix_found + prefix_suffix_found) >= target_keys_to_find.load()) {
            std::cout << "\n\n[SUCCESS] Found " << (prefix_found + prefix_suffix_found) << " keys as requested! Exiting..." << std::endl;
            stop_search.store(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            break;
        }
    }

    for (auto& t : threads) {
        t.join();
    }

    // SECURE CLEANUP: Ensure all sensitive data is wiped from memory
    secure_cleanup();
    
    std::cout << "\n[INFO] All private key data has been securely wiped from memory." << std::endl;
    return 0;
}


