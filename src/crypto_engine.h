#pragma once

#include "types.h"

#include <openssl/evp.h>
#include <optional>
#include <vector>

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    /// Take plaintext and key, return ciphertext
    optional<Bytes> encrypt(Bytes const&, Bytes const&);

    /// Take ciphertext and key, return plaintext
    optional<Bytes> decrypt(Bytes const&, Bytes const&);

private:
    EVP_CIPHER_CTX* ctx;
    static constexpr size_t AES_BLOCK_SIZE = 16;
};
