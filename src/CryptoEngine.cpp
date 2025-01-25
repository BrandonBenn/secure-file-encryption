#include "CryptoEngine.h"

#include <iostream>

CryptoEngine::CryptoEngine()
    : ctx { EVP_CIPHER_CTX_new() }
{
}

CryptoEngine::~CryptoEngine()
{
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
}

optional<Bytes> CryptoEngine::encrypt_data(Bytes const& plaintext, Bytes const& key)
{
    Bytes ciphertext;

    if (!ctx)
        return std::nullopt;

    Bytes iv(AES_BLOCK_SIZE, 0);
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        std::cerr << "EVP_EncryptInit_ex failed\n";
        return std::nullopt;
    }

    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()))) {
        std::cerr << "EVP_EncryptUpdate failed\n";
        return std::nullopt;
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "EVP_EncryptFinal_ex failed\n";
        return std::nullopt;
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

optional<Bytes> CryptoEngine::decrypt_data(Bytes const& ciphertext, Bytes const& key)
{
    int len = 0, plaintext_len = 0;
    Bytes plaintext;

    if (!ctx)
        return std::nullopt;

    Bytes iv(AES_BLOCK_SIZE, 0);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        std::cerr << "EVP_DecryptInit_ex failed\n";
        return std::nullopt;
    }

    plaintext.resize(ciphertext.size());

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        std::cerr << "EVP_DecryptUpdate failed\n";
        return std::nullopt;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "EVP_DecryptFinal_ex failed\n";
        return std::nullopt;
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext;
}

/**
 * References:
 * - https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
