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
#include <vector>

using namespace sfe;

using std::string;
using std::vector;

tpm_manager::tpm_manager() {
  TSS2_RC rc = Esys_Initialize(&ctx, nullptr, nullptr);
  if (rc != TSS2_RC_SUCCESS) {
    std::cerr << "Esys_Initialize failed\n";
    ctx = nullptr;
  }
};

tpm_manager::~tpm_manager() {
  // If created a primary key, flush it from TPM memory
  if (primary_handle != ESYS_TR_NONE && ctx) {
    TSS2_RC rc = Esys_FlushContext(ctx, primary_handle);

    if (rc != TSS2_RC_SUCCESS) {
      std::cerr << "Esys_FlushContext failed: 0x" << std::hex << rc << std::dec
                << std::endl;
    }
  }

  if (ctx) {
    Esys_Finalize(&ctx);
    ctx = nullptr;
  }

  // clang-format off
  if (out_public)      Esys_Free(out_public);
  if (creation_data)   Esys_Free(creation_data);
  if (creation_hash)   Esys_Free(creation_hash);
  if (creation_ticket) Esys_Free(creation_ticket);
  // clang-format on
};

auto tpm_manager::generate_primary_key(const string &key_label) -> bool {
  if (!ctx)
    return false;

  TPM2B_SENSITIVE_CREATE in_sensitive;
  memset(&in_sensitive, 0, sizeof(in_sensitive));

  TPM2B_PUBLIC in_public;
  memset(&in_public, 0, sizeof(in_public));

  in_public.publicArea.type = TPM2_ALG_RSA;
  in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
  in_public.publicArea.objectAttributes =
      TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_DECRYPT |
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;

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
};

auto tpm_manager::seal_key(const vector<uint8_t> &secret_data,
                           string &sealed_private_path,
                           string &sealed_public_path) -> bool {
  if (not ctx or primary_handle == ESYS_TR_NONE) {
    std::cerr << "TPM context is not initialized";
    return false;
  }

  // prepare for secret data
  TPM2B_SENSITIVE_CREATE in_sensitive;
  memset(&in_sensitive, 0, sizeof(in_sensitive));

  // copy secret_data into the data field
  if (secret_data.size() > sizeof(in_sensitive.sensitive.data.buffer)) {
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
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_NODA;

  in_public.publicArea.authPolicy.size = 0;
  in_public.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

  outside_info = nullptr;
  creation_pcr = nullptr;
  out_public = nullptr;
  creation_data = nullptr;
  creation_hash = nullptr;
  creation_ticket = nullptr;
  TPM2B_PRIVATE *out_private = nullptr;

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

    priv_file.write(reinterpret_cast<const char *>(out_private->buffer),
                    out_private->size);
    priv_file.close();
  }

  {
    std::ofstream pub_file(sealed_public_path, std::ios::binary);
    if (!pub_file) {
      std::cerr << "Failed to open" << sealed_private_path << "for writing.";
      return false;
    }

    pub_file.write(reinterpret_cast<const char *>(
                       out_public->publicArea.unique.keyedHash.buffer),
                   out_public->publicArea.unique.keyedHash.size);
    pub_file.close();
  }

  return true;
}
