#include <cuda_runtime.h>
#include <curand_kernel.h>
#include <cuda.h>
#include <cuda_runtime_api.h>

#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA error at %s:%d - %s\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(1); \
        } \
    } while(0)

extern "C" void init_ed25519_constants() {
}

__global__ void generate_random_data_kernel(
    curandState* states,
    uint8_t* seeds,
    uint8_t* privkeys,
    int batch_size,
    int block_size,
    int grid_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;
    
    curandState state = states[idx];
    
    for (int i = 0; i < 32; i++) {
        seeds[idx * 32 + i] = curand(&state) & 0xFF;
    }
    
    for (int i = 0; i < 32; i++) {
        privkeys[idx * 64 + i] = curand(&state) & 0xFF;
    }
    
    privkeys[idx * 64 + 0] &= 0xF8;
    privkeys[idx * 64 + 31] &= 0x7F;
    privkeys[idx * 64 + 31] |= 0x40;
    
    states[idx] = state;
}

extern "C" cudaError_t call_generate_ed25519_keys_kernel(
    curandState* d_states,
    uint8_t* d_seeds,
    uint8_t* d_privkeys,
    int batch_size,
    int block_size,
    int grid_size
) {
    generate_random_data_kernel<<<grid_size, block_size>>>(
        d_states, d_seeds, d_privkeys, batch_size, block_size, grid_size
    );
    
    return cudaGetLastError();
}
