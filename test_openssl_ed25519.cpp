#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <cstring>

// Test OpenSSL Ed25519 key generation
void test_ed25519_keygen() {
    std::cout << "Testing OpenSSL Ed25519 key generation..." << std::endl;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_CRYPTO_strings();
    
    // Seed random number generator
    if (RAND_poll() != 1) {
        std::cout << "Warning: Failed to seed OpenSSL RNG" << std::endl;
    }
    
    // Generate Ed25519 key pair
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx) {
        std::cout << "Failed to create Ed25519 context" << std::endl;
        return;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cout << "Failed to initialize key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cout << "Failed to generate key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    // Extract public key
    size_t pub_len = 32;
    unsigned char pubkey[32];
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &pub_len) <= 0) {
        std::cout << "Failed to extract public key" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    // Extract private key
    size_t priv_len = 32;
    unsigned char privkey[32];
    if (EVP_PKEY_get_raw_private_key(pkey, privkey, &priv_len) <= 0) {
        std::cout << "Failed to extract private key" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    
    std::cout << "✅ Ed25519 key generation successful!" << std::endl;
    std::cout << "Public key length: " << pub_len << " bytes" << std::endl;
    std::cout << "Private key length: " << priv_len << " bytes" << std::endl;
    
    // Display public key in hex
    std::cout << "Public key: ";
    for (size_t i = 0; i < pub_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)pubkey[i];
    }
    std::cout << std::endl;
    
    // Display private key in hex (first few bytes for security)
    std::cout << "Private key (first 8 bytes): ";
    for (size_t i = 0; i < 8 && i < priv_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)privkey[i];
    }
    std::cout << "..." << std::endl;
    
    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    
    std::cout << "✅ Test completed successfully!" << std::endl;
}

int main() {
    std::cout << "🚀 OpenSSL Ed25519 Test Program" << std::endl;
    std::cout << "=================================" << std::endl;
    
    try {
        test_ed25519_keygen();
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "❌ Test failed with unknown exception" << std::endl;
        return 1;
    }
    
    return 0;
}
