/** @file MuSecureBootKeySelectorLib.h

  This header file provides functions to interact with platform supplied
  secure boot related keys through SecureBootKeyStoreLib.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MU_SB_KEY_SELECTOR_LIB_H_
#define MU_SB_KEY_SELECTOR_LIB_H_

typedef struct {
  //
  // Indicates the presence of the legacy keys (2011 - Keys that are being phased out)
  //
  UINT8    ContainsLegacyKeys     : 1;
  //
  // Indicates the presence of the Microsoft keys (Microsoft owned keys, used to sign Microsoft software)
  //
  UINT8    ContainsFirstPartyKeys : 1;
  //
  // Indicates the presence of the third party keys (Owned by Microsoft, used to sign third party software)
  //
  UINT8    ContainsThirdPartyKeys : 1;
  //
  // Indicates the presence of unknown keys (Keys that are not recognized)
  //
  UINT8    ContainsUnknownKeys    : 1;
} SECURE_BOOT_CONFIG_INFO;

//
// Check if the configuration info contains the specified keys
//
#define CONTAINS_LEGACY_KEYS(CONFIG_INFO)                       ((CONFIG_INFO).ContainsLegacyKeys)
#define CONTAINS_ONLY_FIRST_PARTY_KEYS(CONFIG_INFO)             ((CONFIG_INFO).ContainsFirstPartyKeys && !(CONFIG_INFO).ContainsThirdPartyKeys && !(CONFIG_INFO).ContainsUnknownKeys)
#define CONTAINS_ONLY_MODERN_FIRST_PARTY_KEYS(CONFIG_INFO)      ((CONFIG_INFO).ContainsFirstPartyKeys && !(CONFIG_INFO).ContainsLegacyKeys && !(CONFIG_INFO).ContainsUnknownKeys)
#define CONTAINS_FIRST_PARTY_AND_THIRD_PARTY_KEYS(CONFIG_INFO)  ((CONFIG_INFO).ContainsFirstPartyKeys && (CONFIG_INFO).ContainsThirdPartyKeys && !(CONFIG_INFO).ContainsUnknownKeys)
#define CONTAINS_UNKNOWN_KEYS(CONFIG_INFO)                      ((CONFIG_INFO).ContainsUnknownKeys)
#define CONTAINS_NO_KEYS(CONFIG_INFO)                           (!((CONFIG_INFO).ContainsLegacyKeys || (CONFIG_INFO).ContainsFirstPartyKeys || (CONFIG_INFO).ContainsThirdPartyKeys || (CONFIG_INFO).ContainsUnknownKeys))

/**
  Query the index of the actively used Secure Boot keys corresponds to the Secure Boot key store, if it
  can be determined.

  @retval The status of the operation.

**/
EFI_STATUS
EFIAPI
GetCurrentSecureBootConfig (
  SECURE_BOOT_CONFIG_INFO  *ConfigInfo
  );

/**
  Returns the status of setting secure boot keys.

  @param  [in] Index  The index of key from key stores.

  @retval Will return the status of setting secure boot variables.

**/
EFI_STATUS
EFIAPI
SetSecureBootConfig (
  IN  UINT8  Index
  );

/**
  Returns the string associated with with the ConfigInfo.

  @param [in] ConfigInfo  The configuration info to get the string for.

  @retval  Will return the string associated with the ConfigInfo.
**/
CONST CHAR16 *
EFIAPI
GetSecureBootConfigString (
  IN SECURE_BOOT_CONFIG_INFO  ConfigInfo
  );

#endif //MU_SB_KEY_SELECTOR_LIB_H_
