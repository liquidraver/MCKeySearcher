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
#include <sstream>
#include <algorithm>
#include <pthread.h>
#include <numa.h>
#include <immintrin.h>
#include <cpuid.h>
#include <unistd.h>
#include <fcntl.h>

struct Config {
    std::string prefix;
    std::string suffix;
    int search_mode = 1;
    int target_keys = 1;
    bool continuous = false;
    int cpu_threads = 0;
};

std::atomic<uint64_t> total_attempts(0);
std::atomic<int> keys_found(0);
std::atomic<bool> stop_search(false);
std::mutex file_mutex;
std::mutex print_mutex;

std::chrono::steady_clock::time_point program_start_time;

static const char hex_chars[] = "0123456789ABCDEF";

inline void to_hex_fast(const unsigned char* data, size_t len, std::string& out) {
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hex_chars[data[i] >> 4];
        out[2 * i + 1] = hex_chars[data[i] & 0x0F];
    }
}

inline bool check_prefix(const unsigned char* data, const std::string& prefix) {
    size_t prefix_len = prefix.length() / 2;
    
    if (prefix_len > 0) {
        unsigned char high = (prefix[0] >= 'A') ? (prefix[0] - 'A' + 10) : (prefix[0] - '0');
        unsigned char low = (prefix[1] >= 'A') ? (prefix[1] - 'A' + 10) : (prefix[1] - '0');
        unsigned char expected = (high << 4) | low;
        if (data[0] != expected) return false;
    }
    
    if (prefix_len >= 4) {
#ifdef __AVX2__
        uint32_t expected_prefix = 0;
        for (size_t i = 0; i < 4 && i < prefix_len; ++i) {
            unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
            unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
            expected_prefix |= ((high << 4) | low) << (i * 8);
        }
        
        uint32_t data_prefix = *(uint32_t*)data;
        uint32_t mask = (prefix_len >= 4) ? 0xFFFFFFFF : (0xFFFFFFFF >> (8 * (4 - prefix_len)));
        if ((data_prefix & mask) != (expected_prefix & mask)) return false;
        
        for (size_t i = 4; i < prefix_len; ++i) {
            unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
            unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[i] != expected) return false;
        }
#else
        for (size_t i = 1; i < prefix_len; ++i) {
            unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
            unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[i] != expected) return false;
        }
#endif
    } else {
        for (size_t i = 1; i < prefix_len; ++i) {
            unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
            unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[i] != expected) return false;
        }
    }
    
    return true;
}

inline bool check_suffix(const unsigned char* data, const std::string& suffix) {
    size_t suffix_len = suffix.length() / 2;
    size_t start_byte = 32 - suffix_len;
    
    if (suffix_len > 0) {
        unsigned char high = (suffix[2 * (suffix_len - 1)] >= 'A') ? (suffix[2 * (suffix_len - 1)] - 'A' + 10) : (suffix[2 * (suffix_len - 1)] - '0');
        unsigned char low = (suffix[2 * (suffix_len - 1) + 1] >= 'A') ? (suffix[2 * (suffix_len - 1) + 1] - 'A' + 10) : (suffix[2 * (suffix_len - 1) + 1] - '0');
        unsigned char expected = (high << 4) | low;
        if (data[start_byte + suffix_len - 1] != expected) return false;
    }
    
    if (suffix_len >= 4) {
#ifdef __AVX2__
        uint32_t expected_suffix = 0;
        for (size_t i = 0; i < 4 && i < suffix_len; ++i) {
            unsigned char high = (suffix[2 * i] >= 'A') ? (suffix[2 * i] - 'A' + 10) : (suffix[2 * i] - '0');
            unsigned char low = (suffix[2 * i + 1] >= 'A') ? (suffix[2 * i + 1] - 'A' + 10) : (suffix[2 * i + 1] - '0');
            expected_suffix |= ((high << 4) | low) << (i * 8);
        }
        
        uint32_t data_suffix = *(uint32_t*)(data + start_byte);
        uint32_t mask = (suffix_len >= 4) ? 0xFFFFFFFF : (0xFFFFFFFF >> (8 * (4 - suffix_len)));
        if ((data_suffix & mask) != (expected_suffix & mask)) return false;
        
        for (size_t i = 4; i < suffix_len; ++i) {
            unsigned char high = (suffix[2 * i] >= 'A') ? (suffix[2 * i] - 'A' + 10) : (suffix[2 * i] - '0');
            unsigned char low = (suffix[2 * i + 1] >= 'A') ? (suffix[2 * i + 1] - 'A' + 10) : (suffix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[start_byte + i] != expected) return false;
        }
#else
        for (size_t i = 0; i < suffix_len - 1; ++i) {
            unsigned char high = (suffix[2 * i] >= 'A') ? (suffix[2 * i] - 'A' + 10) : (suffix[2 * i] - '0');
            unsigned char low = (suffix[2 * i + 1] >= 'A') ? (suffix[2 * i + 1] - 'A' + 10) : (suffix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[start_byte + i] != expected) return false;
        }
#endif
    } else {
        for (size_t i = 0; i < suffix_len - 1; ++i) {
            unsigned char high = (suffix[2 * i] >= 'A') ? (suffix[2 * i] - 'A' + 10) : (suffix[2 * i] - '0');
            unsigned char low = (suffix[2 * i + 1] >= 'A') ? (suffix[2 * i + 1] - 'A' + 10) : (suffix[2 * i + 1] - '0');
            unsigned char expected = (high << 4) | low;
            if (data[start_byte + i] != expected) return false;
        }
    }
    
    return true;
}

std::string format_duration(std::chrono::milliseconds ms) {
    auto hours = std::chrono::duration_cast<std::chrono::hours>(ms);
    ms -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(ms);
    ms -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ms);
    ms -= seconds;
    
    std::ostringstream oss;
    if (hours.count() > 0) {
        oss << hours.count() << "h " << minutes.count() << "m " << seconds.count() << "s";
    } else if (minutes.count() > 0) {
        oss << minutes.count() << "m " << seconds.count() << "s";
    } else if (seconds.count() > 0) {
        oss << seconds.count() << "s " << ms.count() << "ms";
    } else {
        oss << ms.count() << "ms";
    }
    return oss.str();
}

void log_key(const std::string& priv_hex, const std::string& pub_hex, const std::string& label) {
    std::lock_guard<std::mutex> lock(file_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - program_start_time);
    
    std::ofstream out("found_keys.txt", std::ios::app);
    if (out.is_open()) {
        out << label << ": " << priv_hex << " | " << pub_hex << std::endl;
    }
    
    std::lock_guard<std::mutex> print_lock(print_mutex);
    std::cout << "\n*** KEY FOUND *** Time: " << format_duration(elapsed_ms) << " | " << label << " | " << pub_hex << std::endl;
}

void set_thread_affinity(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    pthread_t current_thread = pthread_self();
    int result = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        static int warning_count = 0;
        if (warning_count < 5) {
            std::cerr << "Warning: Failed to set affinity for thread to CPU " << cpu_id 
                      << " (error " << result << ")" << std::endl;
            warning_count++;
        }
    }
}

struct CPUFeatures {
    bool avx2 = false;
    bool fma = false;
    bool bmi2 = false;
};

CPUFeatures detect_cpu_features() {
    CPUFeatures features;
    
    unsigned int eax, ebx, ecx, edx;
    
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        features.avx2 = (ebx & (1 << 5)) != 0;
        features.fma = (ebx & (1 << 12)) != 0;
        features.bmi2 = (ebx & (1 << 8)) != 0;
    }
    
    return features;
}

void print_status(uint64_t attempts, int found, double keys_per_sec) {
    std::lock_guard<std::mutex> lock(print_mutex);
    
    std::cout << "\r[CPU] Attempts: " << attempts 
              << " | Found: " << found 
              << " | Keys/sec: " << std::fixed << std::setprecision(0) << keys_per_sec
              << "          " << std::flush;
}

void cpu_worker(const Config& config, int thread_id, int cpu_id) {
    set_thread_affinity(cpu_id);
    
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    uint64_t local_attempts = 0;
    const int UPDATE_INTERVAL = 1000;
    
    while (!stop_search.load()) {
        unsigned char pubkey[32], privkey[64];
        
        // Generate cryptographically secure Ed25519 key pair
        randombytes_buf(privkey, 64);
        crypto_sign_ed25519_keypair(pubkey, privkey);
        
        local_attempts++;
        
        bool match = false;
        std::string match_type;
        
        // Check for matches
        if (config.search_mode == 1) {
            match = check_prefix(pubkey, config.prefix);
            if (match) match_type = "CPU-Prefix";
        } else if (config.search_mode == 2) {
            match = check_suffix(pubkey, config.suffix);
            if (match) match_type = "CPU-Suffix";
        } else if (config.search_mode == 3) {
            if (check_prefix(pubkey, config.prefix)) {
                match = check_suffix(pubkey, config.suffix);
                if (match) match_type = "CPU-Prefix+Suffix";
            }
        }
        
        if (match) {
            to_hex_fast(privkey, 64, priv_hex);
            to_hex_fast(pubkey, 32, pub_hex);
            
            log_key(priv_hex, pub_hex, match_type);
            
            keys_found.fetch_add(1);
            
            if (!config.continuous && keys_found.load() >= config.target_keys) {
                stop_search.store(true);
                break;
            }
        }
        
        // Update counters periodically
        if (local_attempts % UPDATE_INTERVAL == 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
    
    if (local_attempts > 0) {
        total_attempts.fetch_add(local_attempts);
    }
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    CPUFeatures cpu_features = detect_cpu_features();
    std::cout << "MCKeySearcher - CPU-Only Ed25519 Key Searcher\n";
    std::cout << "CPU Features:\n";
    std::cout << "  AVX2: " << (cpu_features.avx2 ? "Yes" : "No") << "\n";
    std::cout << "  FMA: " << (cpu_features.fma ? "Yes" : "No") << "\n";
    std::cout << "  BMI2: " << (cpu_features.bmi2 ? "Yes" : "No") << "\n\n";
    
    std::string prefix;
    std::cout << "Enter hex prefix (e.g., BEEF, 1234): ";
    std::cin >> prefix;
    
    if (prefix.empty()) {
        std::cout << "No prefix specified." << std::endl;
        return 1;
    }
    
    for (char c : prefix) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
            std::cout << "Invalid hex prefix. Use only 0-9, A-F." << std::endl;
            return 1;
        }
    }
    
    for (char& c : prefix) {
        if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
    }
    
    Config config;
    config.prefix = prefix;
    
    std::cout << "\nSearch mode:\n";
    std::cout << "1. Prefix only\n";
    std::cout << "2. Suffix only\n";
    std::cout << "3. Prefix + Suffix\n";
    std::cout << "Choice (1-3): ";
    std::cin >> config.search_mode;
    
    if (config.search_mode < 1 || config.search_mode > 3) {
        config.search_mode = 1;
    }
    
    if (config.search_mode == 2 || config.search_mode == 3) {
        std::cout << "\nEnter hex suffix (e.g., BEEF, 1234): ";
        std::cin >> config.suffix;
        
        if (config.suffix.empty()) {
            std::cout << "No suffix specified, defaulting to prefix only." << std::endl;
            config.search_mode = 1;
        } else {
            for (char& c : config.suffix) {
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                    std::cout << "Invalid hex suffix. Use only 0-9, A-F." << std::endl;
                    return 1;
                }
                if (c >= 'a' && c <= 'f') c = c - 'a' + 'A';
            }
        }
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
    
    unsigned int total_cores = std::thread::hardware_concurrency();
    config.cpu_threads = (total_cores > 1) ? total_cores - 1 : 1;
    
    std::cout << "\nSystem Info:\n";
    std::cout << "Total CPU cores: " << total_cores << "\n";
    std::cout << "CPU threads to use: " << config.cpu_threads << " (1 core reserved for OS)\n";
    std::cout << "CPU Architecture: ";
    if (cpu_features.avx2) {
        std::cout << "AVX2 (Modern Desktop)";
    } else {
        std::cout << "Basic x86-64";
    }
    std::cout << "\nSearch mode: ";
    if (config.search_mode == 1) {
        std::cout << "Prefix only (" << config.prefix << ")";
    } else if (config.search_mode == 2) {
        std::cout << "Suffix only (" << config.suffix << ")";
    } else {
        std::cout << "Prefix + Suffix (" << config.prefix << " + " << config.suffix << ")";
    }
    std::cout << "\n\n";
    
    program_start_time = std::chrono::steady_clock::now();
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cout << "Program started at: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << std::endl;
    std::cout << "\nStarting CPU-only search...\n";
    std::cout << "Found keys will be saved to found_keys.txt\n\n";
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < config.cpu_threads; ++i) {
        threads.emplace_back(cpu_worker, std::ref(config), i, i);
    }
    std::cout << "Started " << config.cpu_threads << " CPU worker threads\n";
    
    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_search.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        uint64_t current_attempts = total_attempts.load();
        int current_found = keys_found.load();
        auto now = std::chrono::steady_clock::now();
        
        std::chrono::duration<double> elapsed = now - last_time;
        double keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        print_status(current_attempts, current_found, keys_per_sec);
        
        last_attempts = current_attempts;
        last_time = now;
        
        if (!config.continuous && current_found >= config.target_keys) {
            stop_search.store(true);
            break;
        }
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    std::cout << "\n\nSearch completed! Found " << keys_found.load() << " keys." << std::endl;
    std::cout << "Keys saved to found_keys.txt" << std::endl;
    
    return 0;
}
