#include "file_handler.h"

#include <fstream>

/**
 * Reference:
 * https://gist.github.com/looopTools/64edd6f0be3067971e0595e1e4328cbc
 */

FileHandler::FileHandler(path const& filename)
    : file(filename)
{
}

optional<Bytes> FileHandler::read()
{
    std::ifstream ifile(file, std::ios::in | std::ios::binary);

    if (not ifile.is_open())
        return std::nullopt;

    Bytes data((std::istreambuf_iterator<char>(ifile)),
        std::istreambuf_iterator<char>());
    return data;
}

bool FileHandler::write(Bytes const& content)
{
    std::ofstream ofile(file, std::ios::binary);

    if (not ofile.is_open())
        return false;

    ofile.write(reinterpret_cast<char const*>(content.data()), content.size());

    return true;
}

string FileHandler::filename()
{
    return file.filename().string();
}
