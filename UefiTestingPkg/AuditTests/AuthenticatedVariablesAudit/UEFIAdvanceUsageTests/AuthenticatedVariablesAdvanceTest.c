/** @file
  SecureBootKeysAudit.c

  This Test tests UEFI SetVariable and GetVariable Certificate's and Certificate Chains

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
/
#include <PiPei.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h> // AllocateZero FreePool
#include <Library/BaseMemoryLib.h>

#include "AuthData.h"

// *----------------------------------------------------------------------------------*
// * Defines                                                                          *
// *----------------------------------------------------------------------------------*
#define UNIT_TEST_NAME     "Authenticated Variables Basic Usage Tests"
#define UNIT_TEST_VERSION  "0.1"

#define AUTH_WRITE_ATTR  (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)

#define VARIABLE_KEY_LENGTH_SUPPORT_2048  (0)
#define VARIABLE_KEY_LENGTH_SUPPORT_3072  (1)
#define VARIABLE_KEY_LENGTH_SUPPORT_4096  (2)
#define VARIABLE_KEY_LENGTH_SUPPORT_END   (3)

#define ADDITIONAL_CERTIFICATES_SUPPORT_1   (0)
#define ADDITIONAL_CERTIFICATES_SUPPORT_2   (1)
#define ADDITIONAL_CERTIFICATES_SUPPORT_3   (2)
#define ADDITIONAL_CERTIFICATES_SUPPORT_END (3)

#define INVALID_CERTIFICATE_SUPPORT_VALID   (0)
#define INVALID_CERTIFICATE_SUPPORT_INVALID (1)
#define INVALID_CERTIFICATE_SUPPORT_END     (2)

// This test being tested must only have 2 signatures to test against
#define BASIC_USAGE_2_SIGNATURES_TEST_LENGTH (2)

// This test being tested must only have 3 signatures to test against
#define BASIC_USAGE_3_SIGNATURES_TEST_LENGTH (3)


// *----------------------------------------------------------------------------------*
// * Test Structures                                                                  *
// *----------------------------------------------------------------------------------*
typedef struct {
  CHAR16    *Name;         // Name of the UEFI Variable
  UINT32    Attributes;    // The attributes for the variable
  UINT8     *Data;         // Data to install
  UINT8     *ClearData;    // Data to clear the variable
  UINTN     DataSize;      // Size of the install data
  UINTN     ClearDataSize; // Size of the clear data
  UINT8     *ExpectedData; // The expected result
} VARIABLE_CONTEXT;

typedef struct {
  CHAR16              *TestName;                                   // The test name
  VARIABLE_CONTEXT    Chain[BASIC_USAGE_3_SIGNATURES_TEST_LENGTH]; // The chain
  UINT16              ChainLength;                                 // The length of the chain
  EFI_STATUS          ExpectedStatus1;
} BASIC_USAGE_2_VARIABLES_CHAIN_CONTEXT;

typedef struct {
  CHAR16              *TestName;                                   // The test name
  VARIABLE_CONTEXT    Chain[BASIC_USAGE_3_SIGNATURES_TEST_LENGTH]; // The chain
  UINT16              ChainLength;                                 // The length of the chain
  EFI_STATUS          ExpectedStatus1;
} BASIC_USAGE_3_SIGNATURES_TEST_CONTEXT;


// *----------------------------------------------------------------------------------*
// * Test Contexts                                                                    *
// *----------------------------------------------------------------------------------*
STATIC BASIC_USAGE_3_SIGNATURES_TEST_CONTEXT  mVariableKeyLengthSupport = {
  .TestName                                         = L"Variable Key Length Support",
  .Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .ChainLength     = VARIABLE_KEY_LENGTH_SUPPORT_END,
  .ExpectedStatus1 = UNIT_TEST_PASSED
};

STATIC BASIC_USAGE_3_SIGNATURES_TEST_CONTEXT  mAdditionalCertificateSupport = {
  .TestName                                         = L"Additional Certificates Support",
  .Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .ChainLength     = ADDITIONAL_CERTIFICATES_SUPPORT_END,
  .ExpectedStatus1 = UNIT_TEST_PASSED
};

STATIC BASIC_USAGE_2_SIGNATURES_TEST_CONTEXT  mRougeUpdateSupport = {
  .TestName                                         = L"Invalid Certificiate Support",
  .Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2] =  {
    .Name          = L"MockVar",
    .Data          = NULL, // Not known at compile time
    .DataSize      = 0,    // Not known at compile time
    .ClearData     = NULL, // Not known at compile time
    .ClearDataSize = 0,    // Not known at compile time
    .ExpectedData  = NULL  // Not known at compile time
  },
  .ChainLength     = PREVENT_UPDATE_SUPPORT_END,
  .ExpectedStatus1 = UNIT_TEST_FAILED
};

// *----------------------------------------------------------------------------------*
// * Test Helpers                                                                     *
// *----------------------------------------------------------------------------------*

static
VOID
EFIAPI
SetupVariableKeyLengthSupport (
  VOID
  )
{
  // Ensure that the ChainLength matches a basic usage signature test length
  ASSERT(mVariableKeyLengthSupport.ChainLength == BASIC_USAGE_3_SIGNATURES_TEST_LENGTH);

  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048].Data          = m2048VariableKeyLengthSupportMockVar;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048].DataSize      = m2048VariableKeyLengthSupportMockVarSize;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048].ExpectedData  = m2048VariableKeyLengthSupportMockVarExpected;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048].ClearData     = m2048VariableKeyLengthSupportMockVarEmpty;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_2048].ClearDataSize = m2048VariableKeyLengthSupportMockVarEmptySize;

  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072].Data          = m3072VariableKeyLengthSupportMockVar;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072].DataSize      = m3072VariableKeyLengthSupportMockVarSize;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072].ExpectedData  = m3072VariableKeyLengthSupportMockVarExpected;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072].ClearData     = m3072VariableKeyLengthSupportMockVarEmpty;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_3072].ClearDataSize = m3072VariableKeyLengthSupportMockVarEmptySize;

  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096].Data          = m4096VariableKeyLengthSupportMockVar;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096].DataSize      = m4096VariableKeyLengthSupportMockVarSize;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096].ExpectedData  = m4096VariableKeyLengthSupportMockVarExpected;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096].ClearData     = m4096VariableKeyLengthSupportMockVarEmpty;
  mVariableKeyLengthSupport.Chain[VARIABLE_KEY_LENGTH_SUPPORT_4096].ClearDataSize = m4096VariableKeyLengthSupportMockVarEmptySize;
}

/**
  Basic usage of a Authenticated Variable, sets, gets, and clears the variables in a
  chain of 3 variables

  @param   Context             The test context

  @retval  UNIT_TEST_PASSED             The test passed
  @retval  UNIT_TEST_ERROR_TEST_FAILED  The test failed

**/
static
VOID
EFIAPI
SetupAdditionalCertificates (
  VOID
  )
{  
  // Ensure that the ChainLength matches a basic usage signature test length
  ASSERT(mAdditionalCertificateSupport.ChainLength == BASIC_USAGE_3_SIGNATURES_TEST_LENGTH);

  // Setup the expected chain
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].Data          = m1AdditionalCertificatesMockVar;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].DataSize      = m1AdditionalCertificatesMockVarSize;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ExpectedData  = m1AdditionalCertificatesMockVarExpected;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ClearData     = m1AdditionalCertificatesMockVarEmpty;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ClearDataSize = m1AdditionalCertificatesMockVarEmptySize;

  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].Data          = m2AdditionalCertificatesMockVar;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].DataSize      = m2AdditionalCertificatesMockVarSize;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ExpectedData  = m2AdditionalCertificatesMockVarExpected;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ClearData     = m2AdditionalCertificatesMockVarEmpty;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ClearDataSize = m2AdditionalCertificatesMockVarEmptySize;

  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3].Data          = m3AdditionalCertificatesMockVar;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3].DataSize      = m3AdditionalCertificatesMockVarSize;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3].ExpectedData  = m3AdditionalCertificatesMockVarExpected;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3].ClearData     = m3AdditionalCertificatesMockVarEmpty;
  mAdditionalCertificateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_3].ClearDataSize = m3AdditionalCertificatesMockVarEmptySize;
}

static
VOID
EFIAPI
SetInvalidCertificates (
  VOID
  )
{  
  // Ensure that the ChainLength matches a basic usage signature test length
  ASSERT(mRougeUpdateSupport.ChainLength == BASIC_USAGE_2_SIGNATURES_TEST_LENGTH);

  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].Data          = mRouge;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].DataSize      = m1AdditionalCertificatesMockVarSize;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ExpectedData  = m1AdditionalCertificatesMockVarExpected;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ClearData     = m1AdditionalCertificatesMockVarEmpty;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_1].ClearDataSize = m1AdditionalCertificatesMockVarEmptySize;

  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].Data          = m2AdditionalCertificatesMockVar;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].DataSize      = m2AdditionalCertificatesMockVarSize;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ExpectedData  = m2AdditionalCertificatesMockVarExpected;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ClearData     = m2AdditionalCertificatesMockVarEmpty;
  mRougeUpdateSupport.Chain[ADDITIONAL_CERTIFICATES_SUPPORT_2].ClearDataSize = m2AdditionalCertificatesMockVarEmptySize;

}

// *----------------------------------------------------------------------------------*
// * Test Functions                                                                   *
// *----------------------------------------------------------------------------------*

/**
  Basic usage of a Authenticated Variable, sets, gets, and clears the variables in a
  chain of 3 variables

  @param   Context             The test context

  @retval  UNIT_TEST_PASSED             The test passed
  @retval  UNIT_TEST_ERROR_TEST_FAILED  The test failed

**/
static
UNIT_TEST_STATUS
EFIAPI
BasicUsage3VariablesTest (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  // UINT32              Attributes;
  BASIC_USAGE_3_SIGNATURES_TEST_CONTEXT  *BasicUsageContext;
  // UINTN               DataSize;
  EFI_STATUS  Status;

  // TODO I doin't know if I like this as the default value
  UNIT_TEST_STATUS  TestStatus = UNIT_TEST_ERROR_TEST_FAILED;
  UINT8             *Buffer    = NULL;
  UINTN             BufferSize = 0;
  UINT32            Attributes = 0;
  VARIABLE_CONTEXT  Variable;

  // Grab the context for installing the variable
  BasicUsageContext = (BASIC_USAGE_3_SIGNATURES_TEST_CONTEXT *)Context;

  DEBUG ((DEBUG_INFO, "TESTING %s\n", BasicUsageContext->TestName));

  // ----- For each key in the chain loop over and verify that we can set and clear them ----- //
  for (UINTN i = 0; i < BasicUsageContext->ChainLength; i++) {
    Variable = BasicUsageContext->Chain[i];

    // Set the authenticated varible, if this fails this indicates the crypto package doesn't support that keysize
    Status = gRT->SetVariable (
                               Variable.Name,
                               &gUefiTestingPkgTokenSpaceGuid,
                               AUTH_WRITE_ATTR,
                               Variable.DataSize,
                               Variable.Data
                               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SetVariable of \"%s\" failed. Return code %r\n", BasicUsageContext->TestName, Status));
      goto Exit;
    }

    // ----- All we know at this point is that the variable was claimed to have been set ---- //
    // Retreive the set data buffer size
    Status = gRT->GetVariable (
                               Variable.Name,
                               &gUefiTestingPkgTokenSpaceGuid,
                               &Attributes,
                               &BufferSize,
                               NULL
                               );

    // ----- The Attributes returned should match the attributes set ----- //
    if (Attributes != AUTH_WRITE_ATTR) {
      DEBUG ((DEBUG_ERROR, "GetVariable of \"%s\" in test \"%s\" failed. Attributes incorrect (%u), Return code %r\n",
        Variable.Name, BasicUsageContext->TestName, Attributes, Status));
      goto Exit;
    }

    // ----- Assuming the buffer returned correctly we need to allocate the space to put the data ----- //
    if (Status == EFI_BUFFER_TOO_SMALL) {
      Buffer = AllocateZeroPool (BufferSize);
      if (Buffer == NULL) {
        DEBUG ((DEBUG_ERROR, "AllocateZeroPool Failed\n", Variable.Name, BasicUsageContext->TestName, Attributes, Status));
        goto Exit;
      }
    }

    // ----- Retreive the data originally set in our allocated buffer ----- //
    Status = gRT->GetVariable (
                               Variable.Name,
                               &gUefiTestingPkgTokenSpaceGuid,
                               NULL,
                               &BufferSize,
                               Buffer
                               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "GetVariable of \"%s\" in test \"%s\" failed. Return code %r\n", Variable.Name, BasicUsageContext->TestName, Status));
      goto Exit;
    }

    // ----- Confirm the data has been set correctly ----- //
    if (CompareMem (Buffer, Variable.ExpectedData, BufferSize) != 0) {
      DEBUG ((DEBUG_ERROR, "Data didn't return as expected from GetVariable\n"));
      goto Exit;
    }

    // Allocated buffer is no longer needed
    if (Buffer) {
      FreePool (Buffer);
      Buffer = NULL;
    }

    // ----- Try removing the variable to ensure we can clear them successfully ----- //

    Status = gRT->SetVariable (
                               Variable.Name,
                               &gUefiTestingPkgTokenSpaceGuid,
                               AUTH_WRITE_ATTR,
                               Variable.ClearDataSize,
                               Variable.ClearData
                               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Clearing the Variable \"%s\" of test \"%s\" with SetVariable failed. (Return Code: %r)\n", Variable.Name, BasicUsageContext->TestName, Status));
      continue;
    }

    DEBUG ((DEBUG_INFO, "Variable \"%s\" of test \"%s\" cleared (Return Code: %r)\n", Variable.Name, BasicUsageContext->TestName, Status));
  }

  TestStatus = UNIT_TEST_PASSED;
Exit:

  if (Buffer) {
    FreePool (Buffer);
    Buffer = NULL;
  }

  return TestStatus;
}


// *----------------------------------------------------------------------------------*
// * Test Runner                                                                      *
// *----------------------------------------------------------------------------------*
/**
  Initialize the unit test framework, suite, and unit tests for the
  sample unit tests and run the unit tests.

  @retval  EFI_SUCCESS           All test cases were dispatched.
  @retval  EFI_OUT_OF_RESOURCES  There are not enough resources available to
                                 initialize the unit tests.
**/
EFI_STATUS
EFIAPI
AuthenticatedVariablesBasicTestMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  // Baseline Test
  UNIT_TEST_SUITE_HANDLE  BasicUsageTest;

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
  Status = CreateUnitTestSuite (&BasicUsageTest, Framework, "Basic Usage Test", "SecureBootKeysAudit.2k", NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in CreateUnitTestSuite for Baseline2kKeysTest\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  SetupVariableKeyLengthSupport ();
  SetupAdditionalCertificates ();

  // -----------Suite-----------Description-----------------------Class----------------------------Test Function--------------Pre---Clean--Context
  AddTestCase (BasicUsageTest, "Variable Key Length Support",     "VariableKeyLengthSupport",      BasicUsage3VariablesTest, NULL, NULL, &mVariableKeyLengthSupport);
  AddTestCase (BasicUsageTest, "Additional Certificates Support", "AdditionalCertificatesSupport", BasicUsage3VariablesTest, NULL, NULL, &mAdditionalCertificateSupport);

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
