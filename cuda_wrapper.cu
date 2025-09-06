#include <cuda_runtime.h>
#include <cuda.h>
#include <cuda_runtime_api.h>
#include <stdio.h>
#include <stdlib.h>

#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA error at %s:%d - %s\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
            exit(1); \
        } \
    } while(0)

extern "C" int init_cuda_device() {
    int deviceCount;
    CUDA_CHECK(cudaGetDeviceCount(&deviceCount));
    
    if (deviceCount == 0) {
        fprintf(stderr, "No CUDA devices found\n");
        return -1;
    }
    
    int device = 0;
    CUDA_CHECK(cudaSetDevice(device));
    
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    
    printf("CUDA Device: %s\n", prop.name);
    printf("Compute Capability: %d.%d\n", prop.major, prop.minor);
    printf("Global Memory: %zu MB\n", prop.totalGlobalMem / (1024 * 1024));
    printf("Multiprocessors: %d\n", prop.multiProcessorCount);
    printf("Max Threads per Block: %d\n", prop.maxThreadsPerBlock);
    printf("Max Threads per SM: %d\n", prop.maxThreadsPerMultiProcessor);
    
    return device;
}

extern "C" void* cuda_malloc(size_t size) {
    void* ptr;
    CUDA_CHECK(cudaMalloc(&ptr, size));
    return ptr;
}

extern "C" void cuda_free(void* ptr) {
    CUDA_CHECK(cudaFree(ptr));
}

extern "C" void cuda_memcpy_to_device(void* dst, const void* src, size_t size) {
    CUDA_CHECK(cudaMemcpy(dst, src, size, cudaMemcpyHostToDevice));
}

extern "C" void cuda_memcpy_to_host(void* dst, const void* src, size_t size) {
    CUDA_CHECK(cudaMemcpy(dst, src, size, cudaMemcpyDeviceToHost));
}

extern "C" void cuda_synchronize() {
    CUDA_CHECK(cudaDeviceSynchronize());
}

extern "C" const char* cuda_get_last_error() {
    return cudaGetErrorString(cudaGetLastError());
}

extern "C" void cuda_reset_device() {
    CUDA_CHECK(cudaDeviceReset());
}
