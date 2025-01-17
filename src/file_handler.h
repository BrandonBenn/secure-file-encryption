#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

using std::vector;
using bytes = vector<uint8_t>;

using std::filesystem::path;

class FileHandler {
public:
  FileHandler() = default;
  static bytes read_file(const path &);
  static bool write_file(const path &, const bytes &);

  bytes content;
};
