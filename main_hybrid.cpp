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
#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <pthread.h>
#include <numa.h>
#include <immintrin.h>
#include <cpuid.h>
#include <unistd.h>
#include <fcntl.h>

#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        std::cerr << "CUDA error at " << __FILE__ << ":" << __LINE__ << " - " \
                  << cudaGetErrorString(err) << std::endl; \
        exit(1); \
    } \
} while(0)

struct Config {
    std::string prefix;
    std::string suffix;
    int search_mode = 1;
    int target_keys = 1;
    bool continuous = false;
    bool use_gpu = true;
    bool use_cpu = true;
    int cpu_threads = 0;
    bool numa_aware = true;
    size_t batch_size = 32768;
};

std::atomic<uint64_t> total_attempts(0);
std::atomic<int> keys_found(0);
std::atomic<bool> stop_search(false);
std::mutex file_mutex;
std::mutex print_mutex;

struct NumaBuffer {
    std::vector<unsigned char> seeds;
    std::vector<unsigned char> pubkeys;
    std::vector<unsigned char> privkeys;
    int numa_node;
    
    NumaBuffer(size_t size, int node) : numa_node(node) {
        if (numa_available() >= 0) {
            seeds.resize(size * 32);
            pubkeys.resize(size * 32);
            privkeys.resize(size * 64);
            
            int old_stderr = dup(STDERR_FILENO);
            int dev_null = open("/dev/null", O_WRONLY);
            dup2(dev_null, STDERR_FILENO);
            
            numa_tonode_memory(seeds.data(), seeds.size(), node);
            numa_tonode_memory(pubkeys.data(), pubkeys.size(), node);
            numa_tonode_memory(privkeys.data(), privkeys.size(), node);
            
            dup2(old_stderr, STDERR_FILENO);
            close(dev_null);
            close(old_stderr);
        } else {
            seeds.resize(size * 32);
            pubkeys.resize(size * 32);
            privkeys.resize(size * 64);
        }
    }
};

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
    for (size_t i = 0; i < prefix_len; ++i) {
        unsigned char high = (prefix[2 * i] >= 'A') ? (prefix[2 * i] - 'A' + 10) : (prefix[2 * i] - '0');
        unsigned char low = (prefix[2 * i + 1] >= 'A') ? (prefix[2 * i + 1] - 'A' + 10) : (prefix[2 * i + 1] - '0');
        unsigned char expected = (high << 4) | low;
        if (data[i] != expected) return false;
    }
    return true;
}

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

void log_key(const std::string& priv_hex, const std::string& pub_hex, const std::string& label) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream out("found_keys.txt", std::ios::app);
    if (out.is_open()) {
        out << label << ": " << priv_hex << " | " << pub_hex << std::endl;
    }
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

int get_numa_node(int cpu_id) {
    if (numa_available() >= 0) {
        return numa_node_of_cpu(cpu_id);
    }
    return 0;
}

struct CPUFeatures {
    bool avx2 = false;
    bool avx512f = false;
    bool avx512dq = false;
    bool avx512bw = false;
    bool avx512vl = false;
    bool avx512cd = false;
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
        features.avx512f = (ebx & (1 << 16)) != 0;
        features.avx512dq = (ebx & (1 << 17)) != 0;
        features.avx512bw = (ebx & (1 << 30)) != 0;
        features.avx512vl = (ebx & (1 << 31)) != 0;
        features.avx512cd = (ecx & (1 << 28)) != 0;
    }
    
    return features;
}

std::string get_compiler_flags(const CPUFeatures& features) {
    std::string flags = "-std=c++17 -O3 -fomit-frame-pointer -pthread -DNDEBUG";
    
    if (features.avx2) {
        flags += " -mavx2";
    }
    
    if (features.avx512f && features.avx512dq && features.avx512bw && 
        features.avx512vl && features.avx512cd) {
        flags += " -mavx512f -mavx512dq -mavx512bw -mavx512vl -mavx512cd";
    }
    
    if (features.fma) {
        flags += " -mfma";
    }
    
    if (features.bmi2) {
        flags += " -mbmi2";
    }
    
    return flags;
}

void print_status(uint64_t attempts, int found, double keys_per_sec, const std::string& source) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\r[" << source << "] Attempts: " << attempts 
              << " | Found: " << found 
              << " | Keys/sec: " << std::fixed << std::setprecision(0) << keys_per_sec
              << "          " << std::flush;
}

extern "C" cudaError_t call_generate_ed25519_keys_kernel(
    curandState* d_states,
    uint8_t* d_seeds,
    uint8_t* d_privkeys,
    int batch_size,
    int block_size,
    int grid_size
);

void gpu_worker(const Config& config, int thread_id) {
    const size_t BATCH_SIZE = 131072;
    
    curandState* d_states;
    unsigned char *d_seeds, *d_privkeys;
    
    CUDA_CHECK(cudaMalloc(&d_states, BATCH_SIZE * sizeof(curandState)));
    CUDA_CHECK(cudaMalloc(&d_seeds, BATCH_SIZE * 32));
    CUDA_CHECK(cudaMalloc(&d_privkeys, BATCH_SIZE * 64));
    
    std::vector<unsigned char> h_seeds(BATCH_SIZE * 32);
    std::vector<unsigned char> h_privkeys(BATCH_SIZE * 64);
    
    curandState* h_states = new curandState[BATCH_SIZE];
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        curand_init(1234 + i + thread_id * 1000, 0, 0, &h_states[i]);
    }
    CUDA_CHECK(cudaMemcpy(d_states, h_states, BATCH_SIZE * sizeof(curandState), cudaMemcpyHostToDevice));
    delete[] h_states;
    
    int block_size = 256;
    int grid_size = (BATCH_SIZE + block_size - 1) / block_size;
    
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    uint64_t local_attempts = 0;
    const int UPDATE_INTERVAL = 1000;
    
    while (!stop_search.load()) {
        CUDA_CHECK(call_generate_ed25519_keys_kernel(
            d_states, (uint8_t*)d_seeds, (uint8_t*)d_privkeys, 
            BATCH_SIZE, block_size, grid_size
        ));
        
        CUDA_CHECK(cudaMemcpyAsync(h_seeds.data(), d_seeds, BATCH_SIZE * 32, cudaMemcpyDeviceToHost, 0));
        CUDA_CHECK(cudaMemcpyAsync(h_privkeys.data(), d_privkeys, BATCH_SIZE * 64, cudaMemcpyDeviceToHost, 0));
        
        CUDA_CHECK(cudaDeviceSynchronize());
        
        const size_t CHUNK_SIZE = 16384;
        for (size_t chunk_start = 0; chunk_start < BATCH_SIZE; chunk_start += CHUNK_SIZE) {
            if (stop_search.load()) break;
            
            size_t chunk_end = std::min(chunk_start + CHUNK_SIZE, BATCH_SIZE);
            
            for (size_t i = chunk_start; i < chunk_end; ++i) {
                local_attempts++;
                
                unsigned char computed_pubkey[32];
                crypto_sign_ed25519_keypair(computed_pubkey, &h_privkeys[i * 64]);
                
                bool prefix_match = check_prefix(computed_pubkey, config.prefix);
                
                if (prefix_match) {
                    to_hex_fast(&h_privkeys[i * 64], 64, priv_hex);
                    to_hex_fast(computed_pubkey, 32, pub_hex);
                    
                    if (config.search_mode == 2 && check_suffix(computed_pubkey, config.suffix)) {
                        log_key(priv_hex, pub_hex, "GPU+libsodium-Prefix+Suffix");
                    } else {
                        log_key(priv_hex, pub_hex, "GPU+libsodium-Prefix");
                    }
                    
                    keys_found.fetch_add(1);
                    
                    if (!config.continuous && keys_found.load() >= config.target_keys) {
                        stop_search.store(true);
                        break;
                    }
                }
            }
            
            if (local_attempts % (UPDATE_INTERVAL / 4) == 0) {
                total_attempts.fetch_add(local_attempts);
                local_attempts = 0;
            }
        }
        
        if (local_attempts > 0) {
            total_attempts.fetch_add(local_attempts);
            local_attempts = 0;
        }
    }
    
    CUDA_CHECK(cudaFree(d_states));
    CUDA_CHECK(cudaFree(d_seeds));
    CUDA_CHECK(cudaFree(d_privkeys));
}

void cpu_worker(const Config& config, int thread_id, int cpu_id) {
    set_thread_affinity(cpu_id);
    
    int numa_node = get_numa_node(cpu_id);
    
    NumaBuffer buffers(config.batch_size, numa_node);
    
    std::string pub_hex, priv_hex;
    pub_hex.reserve(64);
    priv_hex.reserve(128);
    
    uint64_t local_attempts = 0;
    const int UPDATE_INTERVAL = 1000;
    
    __builtin_prefetch(buffers.seeds.data(), 0, 3);
    __builtin_prefetch(buffers.pubkeys.data(), 1, 3);
    __builtin_prefetch(buffers.privkeys.data(), 1, 3);
    
    while (!stop_search.load()) {
        for (size_t i = 0; i < config.batch_size; ++i) {
            randombytes_buf(&buffers.seeds[i * 32], 32);
            crypto_sign_ed25519_keypair(&buffers.pubkeys[i * 32], &buffers.privkeys[i * 64]);
        }
        
        for (size_t i = 0; i < config.batch_size; ++i) {
            if (stop_search.load()) break;
            
            local_attempts++;
            
            if (i + 64 < config.batch_size) {
                __builtin_prefetch(&buffers.pubkeys[(i + 64) * 32], 0, 1);
                __builtin_prefetch(&buffers.privkeys[(i + 64) * 64], 0, 1);
            }
            
            bool match = false;
            std::string match_type;
            
            if (config.search_mode == 1) {
                match = check_prefix(&buffers.pubkeys[i * 32], config.prefix);
                if (match) match_type = "CPU-Prefix";
            } else if (config.search_mode == 2) {
                match = check_suffix(&buffers.pubkeys[i * 32], config.suffix);
                if (match) match_type = "CPU-Suffix";
            } else if (config.search_mode == 3) {
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

extern "C" void init_ed25519_constants();

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    CPUFeatures cpu_features = detect_cpu_features();
    std::cout << "🔍 MCKeySearcher - Ed25519 Key Searcher\n";
    std::cout << "CPU Features:\n";
    std::cout << "  AVX2: " << (cpu_features.avx2 ? "✅" : "❌") << "\n";
    std::cout << "  AVX-512: " << (cpu_features.avx512f ? "✅" : "❌") << "\n";
    std::cout << "  FMA: " << (cpu_features.fma ? "✅" : "❌") << "\n";
    std::cout << "  BMI2: " << (cpu_features.bmi2 ? "✅" : "❌") << "\n\n";
    
    bool cuda_available = false;
    cudaDeviceProp prop;
    int device_count = 0;
    
    try {
        cudaError_t err = cudaSetDevice(0);
        if (err == cudaSuccess) {
            err = cudaGetDeviceCount(&device_count);
            if (err == cudaSuccess && device_count > 0) {
                err = cudaGetDeviceProperties(&prop, 0);
                if (err == cudaSuccess) {
                    try {
                        init_ed25519_constants();
                        cuda_available = true;
                    } catch (...) {
                        cuda_available = false;
                    }
                }
            }
        }
    } catch (...) {
        cuda_available = false;
    }
    
    if (cuda_available) {
        std::cout << "🔍 MCKeySearcher - Hybrid CPU+GPU Ed25519 Key Searcher\n";
        std::cout << "🚀 Using GPU: " << prop.name << "\n";
        std::cout << "   Compute Capability: " << prop.major << "." << prop.minor << "\n";
        std::cout << "   Memory: " << (prop.totalGlobalMem / (1024*1024*1024)) << " GB\n\n";
    } else {
        std::cout << "🔍 MCKeySearcher - CPU-Only Ed25519 Key Searcher\n";
        std::cout << "⚠️  CUDA not available, running in CPU-only mode\n\n";
    }
    
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
    if (cpu_features.avx512f) {
        std::cout << "AVX-512 (Server-grade)";
    } else if (cpu_features.avx2) {
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
    if (cuda_available) {
        std::cout << "\nGPU: " << prop.name << "\n";
    } else {
        std::cout << "\nGPU: Not available (CPU-only mode)\n";
    }
    std::cout << "\n";
    
    if (cuda_available) {
        std::cout << "\nStarting hybrid CPU+GPU search...\n";
    } else {
        std::cout << "\nStarting CPU-only search...\n";
    }
    std::cout << "Found keys will be saved to found_keys.txt\n\n";
    
    std::vector<std::thread> threads;
    
    if (cuda_available && config.use_gpu) {
        threads.emplace_back(gpu_worker, std::ref(config), 0);
        std::cout << "Started GPU worker thread (Batch size: 131,072 keys)\n";
        std::cout << "GPU optimization: Asynchronous memory transfers + chunked processing\n";
    }
    
    if (config.use_cpu) {
        for (int i = 0; i < config.cpu_threads; ++i) {
            threads.emplace_back(cpu_worker, std::ref(config), i, i);
        }
        std::cout << "Started " << config.cpu_threads << " CPU worker threads\n";
    }
    
    uint64_t last_attempts = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!stop_search.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        uint64_t current_attempts = total_attempts.load();
        int current_found = keys_found.load();
        auto now = std::chrono::steady_clock::now();
        
        std::chrono::duration<double> elapsed = now - last_time;
        double keys_per_sec = (current_attempts - last_attempts) / elapsed.count();
        
        std::string status_label = cuda_available ? "HYBRID" : "CPU-ONLY";
        print_status(current_attempts, current_found, keys_per_sec, status_label);
        
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

