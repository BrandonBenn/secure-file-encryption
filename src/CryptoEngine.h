#pragma once

#include "Types.h"

#include <openssl/evp.h>
#include <optional>
#include <vector>

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    /// Take plaintext and key, return ciphertext
    optional<Bytes> encrypt_data(Bytes const&, Bytes const&);

    /// Take ciphertext and key, return plaintext
    optional<Bytes> decrypt_data(Bytes const&, Bytes const&);

private:
    EVP_CIPHER_CTX* ctx;
    static constexpr size_t AES_BLOCK_SIZE = 16;
};
