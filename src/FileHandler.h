#pragma once

#include "Types.h"

class FileHandler {
public:
    FileHandler(path const&);
    /// Read file content from disk into bytes
    optional<Bytes> read();

    /// Write bytes onto disk
    bool write(Bytes const&);

private:
    path const filename;
};
