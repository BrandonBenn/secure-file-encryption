#pragma once

#include "types.h"

#include <tss2/tss2_esys.h>

class TpmManager {
public:
    TpmManager();
    TpmManager(string const&, string const&);
    ~TpmManager();
    /// Generate a primary key (RSA) and store its handle
    bool generate_primary_key(string const&);
    /// Seal AES key inside the TPM
    bool seal(Bytes const&);
    bool unseal(Bytes const&);

private:
    bool not_initialized();
    string const& sealed_private_path;
    string const& sealed_public_path;

    /// Holds tdata for the connection to the TPM as well as the metadata for TPM
    /// Resource; such as Transient key
    ESYS_CONTEXT* ctx = nullptr;

    /// Reference to the virtual object inside the ESYS_CONTEXT that holds the
    /// metadata for the corresponding TPM Resource.
    ESYS_TR primary_handle = ESYS_TR_NONE;
    TPM2B_DATA* outside_info = nullptr;
    TPML_PCR_SELECTION* creation_pcr = nullptr;
    TPM2B_PUBLIC* out_public = nullptr;
    TPM2B_CREATION_DATA* creation_data = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* creation_ticket = nullptr;
};
