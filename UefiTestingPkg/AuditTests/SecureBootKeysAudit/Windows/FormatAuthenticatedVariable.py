#!python

import struct
import time
import tempfile
import argparse
import logging
import sys
import uuid
import os

from edk2toollib.utility_functions import DetachedSignWithSignTool

import edk2toollib.uefi.uefi_multi_phase as UEFI_MULTI_PHASE
import edk2toollib.windows.locate_tools as locate_tools

WIN_CERT_TYPE_EFI_GUID = 0x0ef1
WIN_CERT_REVISION = 0x0200
EFI_CERT_TYPE_PKCS7_GUID = '4aafd29d-68df-49ee-8aa9-347d375665a7'

ATTRIBUTE_MAP = {
    "NV": UEFI_MULTI_PHASE.EFI_VARIABLE_NON_VOLATILE,
    "BS": UEFI_MULTI_PHASE.EFI_VARIABLE_BOOTSERVICE_ACCESS,
    "RT": UEFI_MULTI_PHASE.EFI_VARIABLE_RUNTIME_ACCESS,
    "HW": UEFI_MULTI_PHASE.EFI_VARIABLE_HARDWARE_ERROR_RECORD,
    "AW": UEFI_MULTI_PHASE.EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    "AT": UEFI_MULTI_PHASE.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
}

TEMP_FOLDER = tempfile.gettempdir()
DATA_BUFFER_FILE = os.path.join(TEMP_FOLDER, "data.bin")
SIGNATURE_BUFFER_FILE = os.path.join(TEMP_FOLDER, "data.bin.digest")


WINCERT_FMT = '<L2H16s'
WINCERT_FMT_SIZE = struct.calcsize(WINCERT_FMT)

EFI_TIME_FMT = '<H6BLh2B'
EFI_TIME_FMT_SIZE = struct.calcsize(EFI_TIME_FMT)

signtoolpath = locate_tools.FindToolInWinSdk("signtool.exe")

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def export_c_array(args: argparse.Namespace, bin_file: str) -> None:
    """
    Converts a given binary file to a UEFI typed C array

    :param args: argparse arguments passes to the script
    :bin file: binary file to convert
    """

    source_file = args.data_file + ".c"
    header_file = args.data_file + ".h"
    if args.output_dir:
        filename = os.path.split(source_file)[-1]
        source_file = os.path.join(args.output_dir, filename)

    variable_name = args.name
    if args.c_name:
        variable_name = args.c_name    
    
    c_array = f"UINT8 {variable_name}[] = {{"
    with open(bin_file, 'rb') as f:

        start = f.tell()
        f.seek(0, 2)
        end = f.tell()
        f.seek(start)
        length = end - start
        for i, byte in enumerate(f.read()):
            if i % 16 == 0:
                c_array += "\n    "

            c_array += f"{byte:#04x}"

            if i != length-1:
                c_array += ", "

    c_array += "\n};"
    c_array += f"\n\nUINTN {variable_name}Size = sizeof {variable_name};\n\n"

    with open(source_file, 'w') as f:
        f.write(c_array)

    logger.info("Created %s", source_file)

    with open(header_file, 'w') as f:
        f.write(f"extern UINT8 {variable_name}[];\n")
        f.write(f"extern UINTN {variable_name}Size;\n\n")


def parse_args():
    """
    Parses arguments from the command line
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="UTF16 Formated Name of Variable")
    parser.add_argument(
        "guid", help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)", type=uuid.UUID)
    parser.add_argument("certificate",
                        help="Certificate to sign the authenticated data with (Accepted: .pfx, .cer")
    parser.add_argument(
        "data_file", help="Binary file of variable data. An empty file is accepted and will be used to clear the authenticated data")
    parser.add_argument(
        "--cert-password", help="certificate password", default="password")
    parser.add_argument(
        "--attributes", default=["NV", "BS", "RT", "AT"], type=str, nargs='+')
    parser.add_argument("--export-c-array", action="store_true",
                        default=False, help="Exports a given buffer as a C array")
    parser.add_argument(
        "--c-name", help="Override C variable name on export", default=None)
    parser.add_argument(
        "--output-dir", help="Output directory for the signed data", default=None)

    args = parser.parse_args()

    # verify the attributes and calculate
    attributes_value = 0
    for a in args.attributes:
        if a not in ATTRIBUTE_MAP:
            logger.error("%s is not a valid attribute", a)
            sys.exit(1)

        attributes_value |= ATTRIBUTE_MAP[a]

    setattr(args, "attributes_value", attributes_value)

    return args


def main():
    args = parse_args()

    # 1. Create a descriptor
    #   Create an EFI_VARIABLE_AUTHENTICATION_2 descriptor where:
    #   • TimeStamp is set to the current time.
    #   • AuthInfo.CertType is set to EFI_CERT_TYPE_PKCS7_GUID

    # CertType will be set later

    # Generate a  timestamp
    tm = time.localtime()
    efi_time = struct.pack(
        EFI_TIME_FMT,
        tm.tm_year,
        tm.tm_mon,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        0,
        0,
        0,
        0,
        0)

    # Generate the hash data to be digested
    buffer = args.name.encode('utf_16_le') + args.guid.bytes_le + \
        struct.pack('<I', args.attributes_value) + efi_time

    # Save off the variable data, we will need it later
    variable_data = b""
    if args.data_file:
        with open(args.data_file, 'rb') as f:
            variable_data = f.read()
    else:
        args.data_file = args.empty_name

    buffer += variable_data

    # Write the buffer to a temporary location so we can hash it with signtool
    with open(DATA_BUFFER_FILE, 'wb') as f:
        f.write(buffer)

    # 2. Hash the serialization of the values of the VariableName, VendorGuid and Attributes
    # parameters of the SetVariable() call and the TimeStamp component of the
    # EFI_VARIABLE_AUTHENTICATION_2 descriptor followed by the variable’s new value (i.e.
    # the Data parameter’s new variable content). That is, digest = hash (VariableName, VendorGuid,
    # Attributes, TimeStamp, DataNew_variable_content). The NULL character terminating the
    # VariableName value shall not be included in the hash computation

    # 3. Sign the resulting digest using a selected signature scheme (e.g. PKCS #1 v1.5

    # 4. Construct a DER-encoded SignedData structure per PKCS#7 version 1.5 (RFC 2315), which shall
    # be supported both with and without a DER-encoded ContentInfo structure per PKCS#7 version 1.5

    # Use signtool to produce a digest of the variable
    # signtool sign /fd sha256 /p7ce DetachedSignedData /p7co 1.2.840.113549.1.7.2 /p7 "C:\\" /f "Cert.pfx" /p password /debug /v "data.bin"
    out = DetachedSignWithSignTool(signtoolpath, DATA_BUFFER_FILE,
                                   SIGNATURE_BUFFER_FILE, args.certificate, args.cert_password)
    if out != 0:
        logger.error("Signtool Failed")
        sys.exit(1) # Fail

    signature = ""
    with open(SIGNATURE_BUFFER_FILE, 'rb') as f:
        signature = f.read()

    # Set the wincert and authinfo
    wincert = struct.pack(WINCERT_FMT,
                          WINCERT_FMT_SIZE + len(signature),
                          WIN_CERT_REVISION,
                          WIN_CERT_TYPE_EFI_GUID,
                          uuid.UUID(EFI_CERT_TYPE_PKCS7_GUID).bytes_le)

    output_file = args.data_file + ".signed"
    if args.output_dir:
        filename = os.path.split(output_file)[-1]
        output_file = os.path.join(args.output_dir, filename)

    # 5. Set AuthInfo.CertData to the DER-encoded PKCS #7 SignedData value.

    # 6. Construct Data parameter: Construct the SetVariable()’s Data parameter by concatenating the
    # complete, serialized EFI_VARIABLE_AUTHENTICATION_2 descriptor with the new value of the
    # variable (DataNew_variable_content)

    with open(output_file, 'wb') as f:
        f.write(efi_time + wincert + signature + variable_data)

    logger.info("Created %s", output_file)

    if args.export_c_array:
        export_c_array(args, output_file)

    # Success
    sys.exit(0)


main()
