/** @file MuSecureBootKeySelectorLib.c

  This library implements functions to interact with platform supplied
  secure boot related keys through SecureBootKeyStoreLib.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>                               // This has to be here so Protocol/FirmwareVolume2.h doesn't cause errors.
#include <UefiSecureBoot.h>                      // SECURE_BOOT_PAYLOAD_INFO, etc

#include <Guid/ImageAuthentication.h>           // EFI_SIGNATURE_LIST, etc.

#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>                  // CopyMem, etc.
#include <Library/MemoryAllocationLib.h>            // AllocateZeroPool, etc.
#include <Library/DebugLib.h>                       // Tracing
#include <Library/UefiRuntimeServicesTableLib.h>    // gRT
#include <Library/SecureBootVariableLib.h>          // Secure Boot Variables Operations
#include <Library/MuSecureBootKeySelectorLib.h>     // Our header
#include <Library/SecureBootKeyStoreLib.h>          // GetPlatformKeyStore
#include <Library/UefiBootServicesTableLib.h>       // gBS
#include <Protocol/Crypto.h>                        // EFI_CRYPTO_PROTOCOL

#define MS_SB_STATUS_MS_LEGACY  MAX_UINT8 - 1 // These are the thumbprints of the legacy secure boot keys (2011 and losing ability to sign new binaries in 2026)
#define MS_SB_STATUS_MS_MODERN  MAX_UINT8 - 2 // These are the thumbprints of the modern secure boot keys (2023)
#define MS_SB_CONFIG_MS_1P      MAX_UINT8 - 1 // These are the thumbprints of the first party secure boot keys (2011 and 2023)
#define MS_SB_CONFIG_MS_3P      MAX_UINT8 - 2 // These are the thumbprints of the third party secure boot keys (2011 and 2023)
//
// Set the bits that indicate the presence of keys in the configuration info
//
#define SET_LEGACY_KEYS(CONFIG_INFO)       ((CONFIG_INFO)->ContainsLegacyKeys = 1)
#define SET_FIRST_PARTY_KEYS(CONFIG_INFO)  ((CONFIG_INFO)->ContainsFirstPartyKeys = 1)
#define SET_THIRD_PARTY_KEYS(CONFIG_INFO)  ((CONFIG_INFO)->ContainsThirdPartyKeys = 1)
#define SET_UNKNOWN_KEYS(CONFIG_INFO)      ((CONFIG_INFO)->ContainsUnknownKeys = 1)

typedef struct {
  //
  // The configuration of the secure boot keys (First Party, Third Party)
  //
  UINT8    Config;
  //
  // The status of the secure boot keys (Legacy or Modern)
  //
  UINT8    Status;
  //
  // The thumbprint of the secure boot keys (SHA1 hash of the certificate)
  //
  UINT8    Thumbprint[SHA1_DIGEST_SIZE];
} SECURE_BOOT_HASH_ENTRY;

//
// The thumbprints for the legacy secure boot keys
// Thumbprints are SHA1 hashes of the certificates
//
STATIC CONST SECURE_BOOT_HASH_ENTRY  KnownMicrosoftSecureBootThumbprints[4] = {
  { // Microsoft Windows Production PCA 2011
    MS_SB_CONFIG_MS_1P,
    MS_SB_STATUS_MS_LEGACY,
    { 0x58,                0x0A,  0x6F, 0x4C, 0xC4, 0xE4, 0xB6, 0x69, 0xB9, 0xEB, 0xDC, 0x1B, 0x2B, 0x3E, 0x08, 0x7B, 0x80, 0xD0, 0x67, 0x8D }
  },
  { // Microsoft Corporation UEFI CA 2011
    MS_SB_CONFIG_MS_3P,
    MS_SB_STATUS_MS_LEGACY,
    { 0x46,                0xDE,  0xF6, 0x3B, 0x5C, 0xE6, 0x1C, 0xF8, 0xBA, 0x0D, 0xE2, 0xE6, 0x63, 0x9C, 0x10, 0x19, 0xD0, 0xED, 0x14, 0xF3 }
  },
  { // Windows UEFI CA 2023
    MS_SB_CONFIG_MS_1P,
    MS_SB_STATUS_MS_MODERN,
    { 0x45,                0xA0,  0xFA, 0x32, 0x60, 0x47, 0x73, 0xC8, 0x24, 0x33, 0xC3, 0xB7, 0xD5, 0x9E, 0x74, 0x66, 0xB3, 0xAC, 0x0C, 0x67 }
  },
  { // Microsoft UEFI CA 2023
    MS_SB_CONFIG_MS_3P,
    MS_SB_STATUS_MS_MODERN,
    { 0xB5,                0xEE,  0xB4, 0xA6, 0x70, 0x60, 0x48, 0x07, 0x3F, 0x0E, 0xD2, 0x96, 0xE7, 0xF5, 0x80, 0xA7, 0x90, 0xB5, 0x9E, 0xAA }
  }
};

/**
 * Generates a thumbprint for the given image.
 *
 * @param[in]  Certificate      The certificate to generate the thumbprint for.
 * @param[in]  CertificateSize  The size of the certificate.
 * @param[out] Thumbprint       The thumbprint to generate.
 * @return                      The status of the operation.
 **/
EFI_STATUS
GenerateThumbprint (
  IN CONST UINT8  *Certificate,
  IN UINTN        CertificateSize,
  OUT UINT8       *Thumbprint
  )
{
  EFI_STATUS  Status;
  UINT8       Hash[SHA1_DIGEST_SIZE];
  VOID        *Sha1Context;

  //
  // Initialize SHA1 context
  //
  Status = Sha1Init (&Sha1Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Update SHA1 context with the certificate data
  //
  Status = Sha1Update (Sha1Context, Certificate, CertificateSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Finalize SHA1 context and obtain the thumbprint
  //
  Status = Sha1Final (Sha1Context, Hash);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Copy the thumbprint to the output buffer
  //
  CopyMem (Thumbprint, Hash, SHA1_DIGEST_SIZE);

  //
  //  Indicate the thumbprint was generated successfully
  //
  return EFI_SUCCESS;
}

/**
  Query the index of the actively used Secure Boot keys corresponds to the Secure Boot key store, if it
  can be determined.

  @retval The status of the operation.

**/
/**
  Query the index of the actively used Secure Boot keys corresponds to the Secure Boot key store, if it
  can be determined.

  @retval The status of the operation.

**/
EFI_STATUS
EFIAPI
GetCurrentSecureBootConfig (
  SECURE_BOOT_CONFIG_INFO  *ConfigInfo
  )
{
  EFI_STATUS             Status;
  UINTN                  SecureBootVariableSize;
  UINT8                  *SecureBootVariable = NULL;
  UINTN                  Index;
  UINT8                  SecureBootPayloadCount = 0;
  EFI_SIGNATURE_LIST     *CertList;
  EFI_SIGNATURE_DATA     *CertData;
  EDKII_CRYPTO_PROTOCOL  *Crypto;
  UINT8                  *Cert;
  UINTN                  CertCount;
  UINTN                  CertSize;
  UINT8                  Thumbprint[SHA1_DIGEST_SIZE];

  //
  // Validate the input parameters.
  //
  if (ConfigInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Zero out the config info.
  //
  ZeroMem (ConfigInfo, sizeof (SECURE_BOOT_CONFIG_INFO));

  //
  // Determine whether the PK is set.
  //
  // If it's not set, we'll indicate that the ConfigInfo is still valid, but that there are no keys.
  SecureBootVariableSize = 0;
  Status                 = gRT->GetVariable (
                                  EFI_PLATFORM_KEY_NAME,
                                  &gEfiGlobalVariableGuid,
                                  NULL,
                                  &SecureBootVariableSize,
                                  SecureBootVariable
                                  );
  if (Status == EFI_NOT_FOUND) {
    //
    // If the PK is not found, then we are in setup mode.
    // Indicate that there are no keys. ConfigInfo is still valid.
    //
    return EFI_SUCCESS;
  } else if (Status != EFI_BUFFER_TOO_SMALL) {
    //
    // If it's not EFI_BUFFER_TOO_SMALL, then we have an error.
    //
    return Status;
  }

  //
  // Get the size of the secure boot variable.
  //
  SecureBootVariableSize = 0;
  Status                 = gRT->GetVariable (
                                  EFI_IMAGE_SECURITY_DATABASE,
                                  &gEfiImageSecurityDatabaseGuid,
                                  NULL,
                                  &SecureBootVariableSize,
                                  SecureBootVariable
                                  );
  //
  // Only proceed if the error was buffer too small.
  //
  if (Status != EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_ERROR, "Retreiving the DB Failed! Status (%r)", Status));
    return Status;
  }

  //
  // Allocate a buffer to hold the secure boot variable.
  //
  SecureBootVariable = AllocatePool (SecureBootVariableSize);
  if (SecureBootVariable == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Get the secure boot variable.
  //
  Status = gRT->GetVariable (
                  EFI_IMAGE_SECURITY_DATABASE,
                  &gEfiImageSecurityDatabaseGuid,
                  NULL,
                  &SecureBootVariableSize,
                  SecureBootVariable
                  );
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  // The SecureBootVariable is a list of EFI_SIGNATURE_LISTs representing the DB.
  //
  CertList = (EFI_SIGNATURE_LIST *)SecureBootVariable;

  //
  // Iterate through the DB entries.
  //
  while ((SecureBootVariableSize > 0) && (SecureBootVariableSize >= CertList->SignatureListSize)) {
    //
    // If the signature type is not X509, skip it
    //
    if (CompareGuid (&CertList->SignatureType, &gEfiCertX509Guid)) {
      //
      // Otherwise, we have a certificate list and now we need to iterate through the certificates
      //
      CertData  = (EFI_SIGNATURE_DATA *)((UINT8 *)CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
      CertCount = (CertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;

      //
      // Iterate over each certificate in the list
      //
      for (Index = 0; Index < CertCount; Index++) {
        //
        // grab the certificate and its size
        //
        Cert     = CertData->SignatureData;
        CertSize = CertList->SignatureSize - sizeof (EFI_GUID);

        //
        // compute the thumbprint
        //
        Status = GenerateThumbprint (Cert, CertSize, Thumbprint);
        if (EFI_ERROR (Status)) {
          goto Exit;
        }

        //
        // check if the thumbprints matches any of the known thumbprints
        //
        for (Index = 0; Index < ARRAY_SIZE (KnownMicrosoftSecureBootThumbprints); Index++) {
          if (CompareMem (Thumbprint, KnownMicrosoftSecureBootThumbprints[Index].Thumbprint, SHA1_DIGEST_SIZE) == 0) {
            //
            // If the thumbprint matches a known thumbprint, we have a known key
            //
            if (KnownMicrosoftSecureBootThumbprints[Index].Config == MS_SB_CONFIG_MS_1P) {
              SET_FIRST_PARTY_KEYS (ConfigInfo);
            } else if (KnownMicrosoftSecureBootThumbprints[Index].Config == MS_SB_CONFIG_MS_3P) {
              SET_THIRD_PARTY_KEYS (ConfigInfo);
            }

            //
            // Determine if this is a legacy or modern key
            //
            if (KnownMicrosoftSecureBootThumbprints[Index].Status == MS_SB_STATUS_MS_LEGACY) {
              SET_LEGACY_KEYS (ConfigInfo);
            }
          } else {
            //
            // If the thumbprint doesn't match any of the known thumbprints, we have an unknown key
            //
            SET_UNKNOWN_KEYS (ConfigInfo);
          }
        }
      }
    } // else check for signature types
  }

Exit:

  //
  // Clean up if necessary.
  //
  if (SecureBootVariable != NULL) {
    FreePool (SecureBootVariable);
  }

  return Status;
}

/**
  Returns the status of setting secure boot keys.

  @param  [in] Index  The index of key from key stores.

  @retval Will return the status of setting secure boot variables.

**/
EFI_STATUS
EFIAPI
SetSecureBootConfig (
  IN  UINT8  Index
  )
{
  EFI_STATUS                Status;
  UINT8                     SecureBootPayloadCount = 0;
  SECURE_BOOT_PAYLOAD_INFO  *SecureBootPayload     = NULL;

  Status = GetPlatformKeyStore (&SecureBootPayload, &SecureBootPayloadCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Index >= SecureBootPayloadCount) {
    return EFI_INVALID_PARAMETER;
  }

  return SetSecureBootVariablesToDefault (&SecureBootPayload[Index]);
}

/**
  Returns the string associated with with the ConfigInfo.

  @param [in] ConfigInfo  The configuration info to get the string for.

  @retval  Will return the string associated with the ConfigInfo.
**/
CONST CHAR16 *
EFIAPI
GetSecureBootConfigString (
  IN SECURE_BOOT_CONFIG_INFO  ConfigInfo
  )
{

  //
  // Determine the configuration based on the keys present
  //
  // Intentionally not showing the legacy keys in the string because without an understanding of the keys, it's not clear what they are or what they do.
  // Functionally if the legacy keys are present, and any of them are in the DBX, then it's not useful to know that the legacy keys are present.
  // 
  if (CONTAINS_ONLY_FIRST_PARTY_KEYS (ConfigInfo)) {
    return L"Microsoft Only Keys";
  } else if (CONTAINS_FIRST_PARTY_AND_THIRD_PARTY_KEYS(ConfigInfo)) {
    return L"Microsoft and Third Party Keys";
  } else if (CONTAINS_UNKNOWN_KEYS(ConfigInfo)) {
    return L"Custom Configuration";
  }

  return L"Unknown Configuration";
}
