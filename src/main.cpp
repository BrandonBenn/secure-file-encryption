#include "types.h"

#include "crypto_engine.h"
#include "file_handler.h"
#include "tpm_manager.h"
#include <iostream>

int main(int argc, char* argv[])
{

    string command = argv[1];
    string key_label = "primary";
    CryptoEngine crypto;

    if (command == "generate_primary") {
        TpmManager tpm;
        if (not tpm.generate_primary_key(key_label)) {
            std::cerr << "Failed to generate primary key.\n";
            return 1;
        }

        std::cout << "Primary key generated Successfully";
        return 0;
    }

    if (command == "seal_key") {
        if (argc < 5)
            return 1;

        path raw_key_file = argv[2];
        path sealed_priv = argv[3];
        path sealed_pub = argv[4];
        auto tpm = TpmManager(sealed_priv, sealed_pub);

        auto file_handler = FileHandler(raw_key_file);
        Bytes key_data;
        if (auto data = file_handler.read())
            key_data = *data;
        else {
            std::cerr << "Unable to read file: " << file_handler.filename();
            return 1;
        }

        if (not tpm.seal(key_data)) {
            std::cerr << "Seal key operation failed.\n";
            return 1;
        }

        std::cout << "Raw key sealed Successfully.\n";
        return 0;
    }

    if (command == "encrypt") {
        if (argc < 5)
            return 1;

        string in_file = argv[2];
        string out_file = argv[3];
        string sealed_priv = argv[4];
        string sealed_pub = argv[5];

        auto file_handler = FileHandler(in_file);
        Bytes plaintext;

        if (auto content = file_handler.read())
            plaintext = *content;
        else {
            std::cerr << "Unable to read file: " << file_handler.filename();
            return 1;
        }

        auto tpm = TpmManager(sealed_priv, sealed_pub);
        Bytes sealed_key;
        if (not tpm.unseal(sealed_key)) {
            std::cerr << "Failed to unseal key.\n";
            return 1;
        }

        Bytes ciphertext;
        if (auto data = crypto.encrypt(plaintext, sealed_key))
            ciphertext = *data;
        else {
            std::cerr << "Encryption failed or returned empty ciphertext.\n";
            return 1;
        }

        if (not file_handler.write(ciphertext)) {
            std::cerr << "Saving to file failed";
            return 1;
        }

        return 0;
    }

    if (command == "decrypt") {
        if (argc < 5)
            return 1;

        string in_file = argv[2];
        string out_file = argv[3];
        string sealed_priv = argv[4];
        string sealed_pub = argv[5];

        auto file_handler = FileHandler(in_file);
        Bytes ciphertext;

        if (auto content = file_handler.read())
            ciphertext = *content;
        else {
            std::cerr << "Unable to read file: " << file_handler.filename();
            return 1;
        }

        auto tpm = TpmManager(sealed_priv, sealed_pub);
        Bytes sealed_key;
        if (not tpm.unseal(sealed_key)) {
            std::cerr << "Failed to unseal key.\n";
            return 1;
        }

        Bytes plaintext;
        if (auto data = crypto.decrypt(ciphertext, sealed_key))
            plaintext = *data;
        else {
            std::cerr << "Encryption failed or returned empty ciphertext.\n";
            return 1;
        }

        if (not file_handler.write(plaintext)) {
            std::cerr << "Saving to file failed";
            return 1;
        }

        return 0;
    }

    return 0;
}
