#pragma once

#include <openssl/evp.h>
#include <optional>
#include <vector>

namespace sfe {
using std::optional;
using std::vector;

class crypto_engine {
public:
  crypto_engine();
  ~crypto_engine();

  /// Take plaintext and key, return ciphertext
  auto encrypt_data(const std::vector<uint8_t> &, const vector<uint8_t> &)
      -> optional<vector<uint8_t>>;

  /// Take ciphertext and key, return plaintext
  auto decrypt_data(const vector<uint8_t> &, const vector<uint8_t> &)
      -> optional<vector<uint8_t>>;

private:
  EVP_CIPHER_CTX *ctx;
  static constexpr size_t AES_BLOCK_SIZE = 16;
};
}; // namespace sfe
