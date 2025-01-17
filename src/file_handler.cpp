#include "file_handler.h"
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

using std::vector;

bytes FileHandler::read_file(const path &filename) {
  std::ifstream infile(filename, std::ios::binary);
  if (!infile.is_open()) {
    std::cerr << "Unable to open file: " << filename << "\n";
    return {};
  }

  vector<uint8_t> buffer((std::istreambuf_iterator<char>(infile),
                          std::istreambuf_iterator<char>()));

  infile.close();

  return buffer;
}
