#pragma once

#include <string>

using std::string;

class TpmManager {
public:
  TpmManager(const TpmManager &) = default;
  TpmManager(TpmManager &&) = default;
  TpmManager &operator=(const TpmManager &) = default;
  TpmManager &operator=(TpmManager &&) = default;
  bool generate_key(const string &key_label);
  bool seal_key(const string &key_label);

private:
  bool initialize_tpm_context();
  void cleanup_tpm_context();
};
