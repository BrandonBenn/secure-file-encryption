#include "file_handler.h"

#include <cstdint>
#include <fstream>

using namespace sfe;

/**
 * Reference:
 * https://gist.github.com/looopTools/64edd6f0be3067971e0595e1e4328cbc
 */

auto sfe::read_file(const path &filename) -> optional<vector<uint8_t>> {
  std::ifstream infile(filename, std::ios::in | std::ios::binary);

  if (not infile.is_open())
    return std::nullopt;

  vector<uint8_t> data((std::istreambuf_iterator<char>(infile)),
                       std::istreambuf_iterator<char>());
  return data;
}

auto sfe::write_file(const path &path, const vector<uint8_t> &content) -> bool {
  std::ofstream file(path, std::ios::binary);

  if (not file.is_open())
    return false;

  file.write(reinterpret_cast<const char *>(content.data()), content.size());

  return true;
}
