/* Adapted from
 *
 * https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_createprimary.c
 * https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h#L1762
 */

#include "tpm_manager.h"
#include <cstring>
#include <fstream>
#include <ios>
#include <iostream>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

TpmManager::TpmManager(
    string const& sealed_private_path,
    string const& sealed_public_path)
    : sealed_private_path(sealed_private_path)
    , sealed_public_path(sealed_public_path)
{
    TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_Initialize failed\n";
        ctx = nullptr;
    }
}

TpmManager::~TpmManager()
{
    // If created a primary key, flush it from TPM memory
    if (not_initialized()) {
        TSS2_RC rc = Esys_FlushContext(ctx, primary_handle);
        if (rc != TSS2_RC_SUCCESS) {
            std::cerr << "Esys_FlushContext failed: 0x" << std::hex << rc << std::dec
                      << std::endl;
        }
    }

    // clang-format off
  if (ctx) Esys_Finalize(&ctx);
  if (out_public)      Esys_Free(&out_public);
  if (creation_data)   Esys_Free(&creation_data);
  if (creation_hash)   Esys_Free(&creation_hash);
  if (creation_ticket) Esys_Free(&creation_ticket);
    // clang-format on

    ctx = nullptr;
    out_public = nullptr;
    creation_data = nullptr;
    creation_hash = nullptr;
    creation_ticket = nullptr;
}

bool TpmManager::generate_primary_key(string const& key_label)
{
    if (not_initialized()) {
        std::cerr << "TPM context is not initialized";
        return false;
    }

    TPM2B_SENSITIVE_CREATE in_sensitive;
    memset(&in_sensitive, 0, sizeof(in_sensitive));

    TPM2B_PUBLIC in_public;
    memset(&in_public, 0, sizeof(in_public));

    in_public.publicArea.type = TPM2_ALG_RSA;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes =
        // clang-format off
      TPMA_OBJECT_RESTRICTED
      | TPMA_OBJECT_USERWITHAUTH
      | TPMA_OBJECT_SENSITIVEDATAORIGIN
      | TPMA_OBJECT_DECRYPT
      | TPMA_OBJECT_FIXEDTPM
      | TPMA_OBJECT_FIXEDPARENT
      | TPMA_OBJECT_NODA;
    // clang-format on

    in_public.publicArea.authPolicy.size = 0;
    in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    in_public.publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public.publicArea.parameters.rsaDetail.exponent = 0;
    in_public.publicArea.unique.rsa.size = 0;

    out_public = nullptr;
    creation_data = nullptr;
    creation_hash = nullptr;
    creation_ticket = nullptr;

    ESYS_TR new_handle = ESYS_TR_NONE;

    TSS2_RC rc = Esys_CreatePrimary(
        ctx, TPM2_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &in_sensitive, &in_public, outside_info, creation_pcr, &new_handle,
        &out_public, &creation_data, &creation_hash, &creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_CreatePrimary failed, error code: 0x" << std::hex << rc
                  << std::dec << '\n';
        return false;
    }

    return true;
}

bool TpmManager::seal(Bytes const& secret_data)
{
    if (not_initialized()) {
        std::cerr << "TPM context is not initialized";
        return false;
    }

    // prepare for secret data
    TPM2B_SENSITIVE_CREATE in_sensitive;
    memset(&in_sensitive, 0, sizeof(in_sensitive));

    // copy secret_data into the data field
    bool is_secret_too_large = secret_data.size() > sizeof(in_sensitive.sensitive.data.buffer);
    if (is_secret_too_large) {
        std::cerr << "Secret too large to seal.\n";
        return false;
    }

    in_sensitive.sensitive.data.size = secret_data.size();
    memcpy(in_sensitive.sensitive.data.buffer, secret_data.data(),
        secret_data.size());

    // define a sealed data object so we can store data in its private area.
    TPM2B_PUBLIC in_public;
    memset(&in_public, 0, sizeof(in_public));

    in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes =
        // clang-format off
      TPMA_OBJECT_FIXEDTPM
      | TPMA_OBJECT_FIXEDPARENT
      | TPMA_OBJECT_SENSITIVEDATAORIGIN
      | TPMA_OBJECT_NODA;
    // clang-format on

    in_public.publicArea.authPolicy.size = 0;
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    outside_info = nullptr;
    creation_pcr = nullptr;
    out_public = nullptr;
    creation_data = nullptr;
    creation_hash = nullptr;
    creation_ticket = nullptr;
    TPM2B_PRIVATE* out_private = nullptr;

    TSS2_RC rc = Esys_Create(
        ctx, primary_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &in_sensitive, &in_public, outside_info, creation_pcr, &out_private,
        &out_public, &creation_data, &creation_hash, &creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_create failed, error code: 0x" << std::hex << rc
                  << std::dec << '\n';
        return false;
    }

    std::cout << "Successfully created sealed object.\n";

    {
        std::ofstream priv_file(sealed_private_path, std::ios::binary);
        if (!priv_file) {
            std::cerr << "Failed to open" << sealed_private_path << "for writing.";
            return false;
        }

        priv_file.write(reinterpret_cast<char const*>(out_private->buffer),
            out_private->size);
        priv_file.close();
    }

    {
        std::ofstream pub_file(sealed_public_path, std::ios::binary);
        if (!pub_file) {
            std::cerr << "Failed to open" << sealed_private_path << "for writing.";
            return false;
        }

        pub_file.write(
            reinterpret_cast<char const*>(out_public->publicArea.unique.keyedHash.buffer),
            out_public->publicArea.unique.keyedHash.size);

        pub_file.close();
    }

    return true;
}

bool TpmManager::unseal(Bytes const& unsealed_data)
{
    std::ifstream priv_file(sealed_private_path, std::ios::binary);
    if (not priv_file) {
        std::cerr << "Cannot open private data file: " << sealed_private_path << '\n';
        return false;
    }

    Bytes private_buf((std::istreambuf_iterator<char>(priv_file)), (std::istreambuf_iterator<char>()));
    priv_file.close();

    std::ifstream pub_file(sealed_public_path);
    if (not pub_file) {
        std::cerr << "Cannot open public data file: " << sealed_public_path << '\n';
        return false;
    }

    Bytes public_buf((std::istreambuf_iterator<char>(pub_file)), (std::istreambuf_iterator<char>()));
    pub_file.close();

    TPM2B_PRIVATE in_private;
    TPM2B_PUBLIC in_public;
    memset(&in_private, 0, sizeof(in_private));
    memset(&in_public, 0, sizeof(in_public));

    bool priv_buf_too_large = (private_buf.size() > sizeof(in_private.buffer));
    if (priv_buf_too_large) {
        std::cerr << "Privaate blob size too large.\n";
        return false;
    }

    in_private.size = private_buf.size();
    memcpy(in_private.buffer, private_buf.data(), private_buf.size());

    in_public.publicArea.type = TPM2_ALG_KEYEDHASH;
    in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public.publicArea.objectAttributes = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA);
    in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    bool public_buf_too_large = public_buf.size() > sizeof(in_public.publicArea.unique.keyedHash.buffer);
    if (public_buf_too_large) {
        std::cerr << "Public blob size too large.\n";
        return false;
    }

    ESYS_TR sealed_handle = ESYS_TR_NONE;
    TSS2_RC rc = Esys_Load(
        ctx,
        primary_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &in_private,
        &in_public,
        &sealed_handle);

    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_Load failed: 0x" << std::hex << rc << std::dec << std::endl;
        return false;
    }

    // (4) Esys_Unseal
    TPM2B_SENSITIVE_DATA* out_data = nullptr;
    rc = Esys_Unseal(
        ctx,
        sealed_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &out_data);

    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_Unseal failed: 0x" << std::hex << rc << std::dec << std::endl;
        // Make sure to flush the handle
        Esys_FlushContext(ctx, sealed_handle);
        return false;
    }

    // (5) Copy the unsealed secret to our output
    // unsealed_data.resize(out_data->size);
    // unsealed_data.emplace_back

    // memcpy(unsealed_data.data(), out_data->buffer, out_data->size);

    std::cout << "Successfully unsealed data. Size: " << out_data->size << " bytes\n";

    // (6) Cleanup
    Esys_Free(&out_data);

    rc = Esys_FlushContext(ctx, sealed_handle);
    if (rc != TSS2_RC_SUCCESS) {
        std::cerr << "Esys_FlushContext failed on sealed object handle: 0x"
                  << std::hex << rc << std::dec << std::endl;
        return false;
    }

    return true;
}

bool TpmManager::not_initialized()
{
    return !ctx or primary_handle == ESYS_TR_NONE;
}
