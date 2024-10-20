/** @file

Copyright (c) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Register/ArchitecturalMsr.h>
#include <Library/UnitTestLib.h>

UNIT_TEST_STATUS
EFIAPI
UefiHardwareNxProtectionEnabled (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MSR_IA32_EFER_REGISTER  Efer;

  Efer.Uint64 = AsmReadMsr64 (MSR_IA32_EFER);
  if (Efer.Bits.NXE == 1) {
    return UNIT_TEST_PASSED;
  }

  UT_LOG_WARNING ("Efer set as 0x%x\n", Efer);
  return UNIT_TEST_ERROR_TEST_FAILED;
}
