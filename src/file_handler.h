#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace sfe {
using std::optional;
using std::vector;
using std::filesystem::path;

/// Read file content from disk into bytes
auto read_file(const path &) -> optional<vector<uint8_t>>;

/// Write bytes onto disk
auto write_file(const path &, const vector<uint8_t> &) -> bool;

}; // namespace sfe
