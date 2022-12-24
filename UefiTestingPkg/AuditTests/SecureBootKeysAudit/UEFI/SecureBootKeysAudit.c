/** @file
  TODO

  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <PiPei.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h> // AllocateZero FreePool

#include "AuthData.h"

#define UNIT_TEST_NAME     "Secure Boot Keys Audit Test"
#define UNIT_TEST_VERSION  "0.1"

#define MOCK_PLATFORM_KEY_INDEX      (0)
#define MOCK_KEY_EXCHANGE_KEY_INDEX  (1)
#define MOCK_LEAF_CERTIFICATE_INDEX  (2)
#define CHAIN_LENGTH                 (3)


typedef struct {
  CHAR16    *Variable;         // Name of the UEFI Variable
  UINT32    Attributes;        // The attributes for the variable
  UINT8     *Data;             // Data to install "Hello <variable>"
  UINT8     *ClearData;        // Data to clear the variable
  UINTN     DataSize;          // Size of the install data
  UINTN     ClearDataSize;     // Size of the clear data
} VARIABLE_CONTEXT;

// This verifies that a given chain of certificates may be installed and cleared successfully
typedef struct {
  CHAR16              *TestName;           // The test name
  VARIABLE_CONTEXT    Chain[CHAIN_LENGTH]; // The chain
  UINT16              ChainLength;         // The length of the chain
  EFI_STATUS          ExpectedStatus1;
} BASIC_INSTALL_CHAIN_CONTEXT;

// UEFI variables must have the same name, guid, and attributes to be accepted

STATIC BASIC_INSTALL_CHAIN_CONTEXT m2kInstall = {
  .TestName                       = L"Basic Install Chain",
  .Chain[MOCK_PLATFORM_KEY_INDEX] =  {
    .Variable   = L"MockPK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_KEY_EXCHANGE_KEY_INDEX] =  {
    .Variable   = L"MockKEK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_LEAF_CERTIFICATE_INDEX] =  {
    .Variable   = L"MockLeaf",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .ChainLength     = CHAIN_LENGTH,
  .ExpectedStatus1 = UNIT_TEST_PASSED
};

STATIC BASIC_INSTALL_CHAIN_CONTEXT m3kInstall = {
  .TestName                       = L"3k Install Chain",
  .Chain[MOCK_PLATFORM_KEY_INDEX] =  {
    .Variable   = L"MockPK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_KEY_EXCHANGE_KEY_INDEX] =  {
    .Variable   = L"MockKEK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_LEAF_CERTIFICATE_INDEX] =  {
    .Variable   = L"MockLeaf",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .ChainLength     = CHAIN_LENGTH,
  .ExpectedStatus1 = UNIT_TEST_PASSED
};

STATIC BASIC_INSTALL_CHAIN_CONTEXT m4kInstall = {
  .TestName                       = L"4k Install Chain",
  .Chain[MOCK_PLATFORM_KEY_INDEX] =  {
    .Variable   = L"MockPK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_KEY_EXCHANGE_KEY_INDEX] =  {
    .Variable   = L"MockKEK",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .Chain[MOCK_LEAF_CERTIFICATE_INDEX] =  {
    .Variable   = L"MockLeaf",
    .Attributes =  EFI_VARIABLE_NON_VOLATILE
                  | EFI_VARIABLE_RUNTIME_ACCESS
                  | EFI_VARIABLE_BOOTSERVICE_ACCESS
                  | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0     // Not known at compile time
  },
  .ChainLength     = CHAIN_LENGTH,
  .ExpectedStatus1 = UNIT_TEST_PASSED
};

static
UNIT_TEST_STATUS
EFIAPI
InstallMockChain (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  // UINT32              Attributes;
  BASIC_INSTALL_CHAIN_CONTEXT  *Btc;
  // UINTN               DataSize;
  EFI_STATUS  Status;

  // TODO I doin't know if I like this as the default value
  UNIT_TEST_STATUS  TestStatus = UNIT_TEST_ERROR_TEST_FAILED;
  UINT8             *Buffer    = NULL;
  UINTN             BufferSize = 0;
  UINT32            Attributes = 0;
  VARIABLE_CONTEXT  Var;

  // EFI_STATUS          ExpectedStatus;

  // Grab the context for installing the variable
  Btc = (BASIC_INSTALL_CHAIN_CONTEXT *)Context;

  // ----- For each key in the chain loop over and verify that we can set and clear them ----- //
  for (UINTN i = 0; i < Btc->ChainLength; i++) {
    Var = Btc->Chain[i];

    // Set the authenticated varible, if this fails this indicates the crypto package doesn't support that keysize
    Status = gRT->SetVariable (
                               Var.Variable,
                               &gUefiTestingPkgTokenSpaceGuid,
                               Var.Attributes,
                               Var.DataSize,
                               Var.Data
                               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SetVariable of \"%s\" failed. Return code %r\n", Btc->TestName, Status));
      goto Exit;
    }

    // ----- All we know at this point is that the variable was claimed to have been set ---- //

    // Retreive the set data buffer size
    Status = gRT->GetVariable (
                               Var.Variable,
                               &gUefiTestingPkgTokenSpaceGuid,
                               &Attributes,
                               &BufferSize,
                               NULL
                               );

    // ----- The Attributes returned should match the attributes set ----- //
    if (Attributes != Var.Attributes) {
      DEBUG ((DEBUG_ERROR, "GetVariable of \"%s\" in test \"%s\" failed. Attributes incorrect (%u), Return code %r\n", Var.Variable, Btc->TestName, Attributes, Status));
      goto Exit;
    }

    if (Status == EFI_BUFFER_TOO_SMALL) {
      Buffer = AllocateZeroPool (BufferSize);
      if (Buffer == NULL) {
        DEBUG ((DEBUG_ERROR, "AllocateZeroPool Failed\n", Var.Variable, Btc->TestName, Attributes, Status));
        goto Exit;
      }
    }

    // Retreive the set data
    Status = gRT->GetVariable (
                               Var.Variable,
                               &gUefiTestingPkgTokenSpaceGuid,
                               NULL,
                               &BufferSize,
                               Buffer
                               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "GetVariable of \"%s\" in test \"%s\" failed. Return code %r\n", Var.Variable, Btc->TestName, Status));
      goto Exit;
    }

    DEBUG ((DEBUG_INFO, "GetVariable of \"%s\" - sizeof(%u) Return code %r\n", Var.Variable, BufferSize, Status));

    DUMP_HEX (DEBUG_INFO, 0, Buffer, BufferSize, "");
  }

  // ----- Begin removing the variables to ensure we can clear them successfully ----- //
  for (UINTN i = 0; i < Btc->ChainLength; i++) {
    Var    = Btc->Chain[i];
    Status = gRT->SetVariable (
                               Var.Variable,
                               &gUefiTestingPkgTokenSpaceGuid,
                               Var.Attributes,
                               Var.ClearDataSize,
                               Var.ClearData
                               );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Clearing the Variable \"%s\" of test \"%s\" with SetVariable failed. Return code %r\n", Var.Variable, Btc->TestName, Status));
      goto Exit;
    }

    DEBUG ((DEBUG_INFO, "Variable \"%s\" of test \"%s\" cleared\n", Var.Variable, Btc->TestName, Status));
  }

  TestStatus = UNIT_TEST_PASSED;
Exit:

  if (Buffer) {
    FreePool (Buffer);
    Buffer = NULL;
  }

  return TestStatus;
}

static
UNIT_TEST_STATUS
EFIAPI
UpdateVariable (
  IN UNIT_TEST_CONTEXT Context
  )
{

}

/**
  Initialize the unit test framework, suite, and unit tests for the
  sample unit tests and run the unit tests.

  @retval  EFI_SUCCESS           All test cases were dispatched.
  @retval  EFI_OUT_OF_RESOURCES  There are not enough resources available to
                                 initialize the unit tests.
**/
EFI_STATUS
EFIAPI
SecureBootKeysAuditMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  // Baseline Test
  UNIT_TEST_SUITE_HANDLE  BaselineKeysTest;

  // Test Imitating Factory shipping with 3k Keys
  // UNIT_TEST_SUITE_HANDLE      Support3kKeysTest;
  // Test Imitating OEM upgrading Keys 2k -> 3k
  // UNIT_TEST_SUITE_HANDLE      Upgrade2kTo3kKeysTest;
  // Test Imitating Factory shipping with 4k Keys
  // UNIT_TEST_SUITE_HANDLE      Support4kKeysTest;
  // Test Imitating OEM upgrading Keys 3k -> 4k
  // UNIT_TEST_SUITE_HANDLE      Upgrade3kTo4kKeysTest;

  // TODO as these get

  Framework = NULL;

  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_NAME, UNIT_TEST_VERSION));

  //
  // Start setting up the test framework for running the tests.
  //
  Status = InitUnitTestFramework (&Framework, UNIT_TEST_NAME, gEfiCallerBaseName, UNIT_TEST_VERSION);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  //
  // Populate the Baseline2kKeysTest Unit Test Suite.
  //
  Status = CreateUnitTestSuite (&BaselineKeysTest, Framework, "Baseline 2K Keys Test", "SecureBootKeysAudit.2k", NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in CreateUnitTestSuite for Baseline2kKeysTest\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  // TODO convert this to a list
  // The platform Key
  m2kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].Data          = m2kMockPK;
  m2kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].DataSize      = m2kMockPKSize;
  m2kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearData     = m2kMockPKDelete;
  m2kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearDataSize = m2kMockPKDeleteSize;

  // The Key Exchange Key
  m2kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].Data          = m2kMockKEK;
  m2kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].DataSize      = m2kMockKEKSize;
  m2kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearData     = m2kMockKEKDelete;
  m2kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearDataSize = m2kMockKEKDeleteSize;

  // The Key Exchange Key
  m2kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].Data          = m2kMockLeaf;
  m2kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].DataSize      = m2kMockLeafSize;
  m2kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearData     = m2kMockLeafDelete;
  m2kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearDataSize = m2kMockLeafDeleteSize;

  // 1.1 Install the MockPK
  //    This will act as a platform Key for the rest of the Variables
  // -----------Suite-----------Description-------------Class-------------------Test Function-------------Pre---Clean-Context
  AddTestCase (BaselineKeysTest, "2kKeysTest", "2kKeysTest", InstallMockChain, NULL, NULL, &m2kInstall);

  m3kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].Data          = m3kMockPK;
  m3kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].DataSize      = m3kMockPKSize;
  m3kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearData     = m3kMockPKDelete;
  m3kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearDataSize = m3kMockPKDeleteSize;

  // The Key Exchange Key
  m3kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].Data          = m3kMockKEK;
  m3kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].DataSize      = m3kMockKEKSize;
  m3kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearData     = m3kMockKEKDelete;
  m3kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearDataSize = m3kMockKEKDeleteSize;

  // The Key Exchange Key
  m3kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].Data          = m3kMockLeaf;
  m3kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].DataSize      = m3kMockLeafSize;
  m3kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearData     = m3kMockLeafDelete;
  m3kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearDataSize = m3kMockLeafDeleteSize;

  AddTestCase (BaselineKeysTest, "3kKeysTest", "3kKeysTest", InstallMockChain, NULL, NULL, &m3kInstall);
  
  m4kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].Data          = m4kMockPK;
  m4kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].DataSize      = m4kMockPKSize;
  m4kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearData     = m4kMockPKDelete;
  m4kInstall.Chain[MOCK_PLATFORM_KEY_INDEX].ClearDataSize = m4kMockPKDeleteSize;

  // The Key Exchange Key
  m4kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].Data          = m4kMockKEK;
  m4kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].DataSize      = m4kMockKEKSize;
  m4kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearData     = m4kMockKEKDelete;
  m4kInstall.Chain[MOCK_KEY_EXCHANGE_KEY_INDEX].ClearDataSize = m4kMockKEKDeleteSize;

  // The Key Exchange Key
  m4kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].Data          = m4kMockLeaf;
  m4kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].DataSize      = m4kMockLeafSize;
  m4kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearData     = m4kMockLeafDelete;
  m4kInstall.Chain[MOCK_LEAF_CERTIFICATE_INDEX].ClearDataSize = m4kMockLeafDeleteSize;

  AddTestCase (BaselineKeysTest, "4kKeysTest", "4kKeysTest", InstallMockChain, NULL, NULL, &m4kInstall);

  //
  // Execute the tests.
  //
  Status = RunAllTestSuites (Framework);
  DEBUG ((DEBUG_INFO, "SecureBootKeysAudit - Return Code %r\n", Status));

EXIT:
  if (Framework) {
    FreeUnitTestFramework (Framework);
  }

  return Status;
}
