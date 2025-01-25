#include "FileHandler.h"

#include <fstream>

/**
 * Reference:
 * https://gist.github.com/looopTools/64edd6f0be3067971e0595e1e4328cbc
 */

FileHandler::FileHandler(path const& filename)
    : filename(filename)
{
}

optional<Bytes> FileHandler::read()
{
    std::ifstream infile(filename, std::ios::in | std::ios::binary);

    if (not infile.is_open())
        return std::nullopt;

    Bytes data((std::istreambuf_iterator<char>(infile)),
        std::istreambuf_iterator<char>());
    return data;
}

bool FileHandler::write(Bytes const& content)
{
    std::ofstream file(filename, std::ios::binary);

    if (not file.is_open())
        return false;

    file.write(reinterpret_cast<char const*>(content.data()), content.size());

    return true;
}
