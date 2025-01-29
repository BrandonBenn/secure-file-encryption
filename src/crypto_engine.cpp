#include "crypto_engine.h"

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

optional<Bytes> CryptoEngine::encrypt(Bytes const& plaintext, Bytes const& key)
{
    Bytes ciphertext;

    if (!ctx)
        return std::nullopt;

    Bytes iv(AES_BLOCK_SIZE, 0);

    auto encrypt_init = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    bool encrypt_init_failed = 1 != encrypt_init;
    if (encrypt_init_failed) {
        std::cerr << "EVP_EncryptInit_ex failed\n";
        return std::nullopt;
    }

    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    auto encrypt_update = EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()));
    bool encrypt_update_failed = 1 != encrypt_update;

    if (encrypt_init_failed) {
        std::cerr << "EVP_EncryptUpdate failed\n";
        return std::nullopt;
    }

    ciphertext_len = len;

    auto encrypt_final = EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    bool encrypt_final_failed = 1 != encrypt_final;

    if (encrypt_final_failed) {
        std::cerr << "EVP_EncryptFinal_ex failed\n";
        return std::nullopt;
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

optional<Bytes> CryptoEngine::decrypt(Bytes const& ciphertext, Bytes const& key)
{
    int len = 0, plaintext_len = 0;
    Bytes plaintext;

    if (!ctx)
        return std::nullopt;

    Bytes iv(AES_BLOCK_SIZE, 0);

    auto decrypt_init = EVP_DecryptInit_ex(
        ctx, EVP_aes_256_cbc(),
        nullptr, key.data(), iv.data());

    bool decrypt_init_failed = 1 != decrypt_init;

    if (decrypt_init_failed) {
        std::cerr << "EVP_DecryptInit_ex failed\n";
        return std::nullopt;
    }

    plaintext.resize(ciphertext.size());

    auto decrypt_updated = EVP_DecryptUpdate(
        ctx, plaintext.data(), &len,
        ciphertext.data(), static_cast<int>(ciphertext.size()));

    bool decrypt_update_failed = 1 != decrypt_updated;

    if (decrypt_update_failed) {
        std::cerr << "EVP_DecryptUpdate failed\n";
        return std::nullopt;
    }
    plaintext_len = len;

    auto decrypt_final = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    bool decrypt_final_failed = 1 != decrypt_final;

    if (decrypt_final_failed) {
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
