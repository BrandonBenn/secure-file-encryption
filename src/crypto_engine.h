#pragma once

#include <cstdint>
#include <vector>

using std::vector;
using bytes = vector<uint8_t>;

#include <openssl/evp.h>

class CryptoEngine {
public:
  CryptoEngine();
  ~CryptoEngine();
  bytes encrypt_data(const bytes &, const bytes &);
  bytes decrypt_data(const bytes &, const bytes &);

private:
  EVP_CIPHER_CTX *ctx;
  static constexpr size_t AES_BLOCK_SIZE = 16;
};
