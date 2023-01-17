#!python

"""
 Imitates Format-SecureBootUefi and signs a variable in accordance with EFI_AUTHENTICATION_2
https://github.com/pyasn1/pyasn1

 https://security.stackexchange.com/questions/249610/what-is-the-pkcs7-detached-signature-format
"""

import struct
import time
import tempfile
import argparse
import logging
import sys
import uuid
import os
import shutil


from edk2toollib.utility_functions import DetachedSignWithSignTool

import edk2toollib.uefi.uefi_multi_phase as UEFI_MULTI_PHASE
import edk2toollib.windows.locate_tools as locate_tools

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import pkcs12

#from pyasn1.codec.native.decoder import decode
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.encoder import encode as nat_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from pyasn1_modules import rfc2315
# pyasn1
# pyasn1_modules


WIN_CERT_TYPE_EFI_GUID = 0x0ef1
WIN_CERT_REVISION_2_0 = 0x0200
EFI_CERT_TYPE_PKCS7_GUID = '4aafd29d-68df-49ee-8aa9-347d375665a7'

ATTRIBUTE_MAP = {
    "NV": UEFI_MULTI_PHASE.EFI_VARIABLE_NON_VOLATILE,
    "BS": UEFI_MULTI_PHASE.EFI_VARIABLE_BOOTSERVICE_ACCESS,
    "RT": UEFI_MULTI_PHASE.EFI_VARIABLE_RUNTIME_ACCESS,
    # Disabling the following two, because they are unsupported (by this script) and deprecated (in UEFI)
    # "HW": UEFI_MULTI_PHASE.EFI_VARIABLE_HARDWARE_ERROR_RECORD,
    # "AW": UEFI_MULTI_PHASE.EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS,
    "AT": UEFI_MULTI_PHASE.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
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


def export_c_array(bin_file: str, output_dir: str, name: str, c_name: str) -> None:
    """
    Converts a given binary file to a UEFI typed C array

    :param args: argparse arguments passes to the script
    :bin file: binary file to convert
    """

    source_file = bin_file + ".c"
    header_file = bin_file + ".h"
    if output_dir:
        filename = os.path.split(source_file)[-1]
        source_file = os.path.join(output_dir, filename)

    variable_name = name
    if c_name:
        variable_name = c_name

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

    logger.info("Created %s", header_file)


def parse_args():
    """
    Parses arguments from the command line
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("name", help="UTF16 Formated Name of Variable")
    parser.add_argument(
        "guid", help="UUID of the namespace the variable belongs to. (Ex. 12345678-1234-1234-1234-123456789abc)", type=uuid.UUID)
    parser.add_argument(
        "attributes", type=str, help="Variable Attributes, AT is a required (Ex \"NV,BT,RT,AT\")")
    parser.add_argument(
        "data_file", help="Binary file of variable data. An empty file is accepted and will be used to cle ar the authenticated data")
    parser.add_argument("certificate",
                        help="Certificate to sign the authenticated data with (Accepted: .pfx)")
    parser.add_argument(
        "--cert-password", help="certificate password", default="password")
    parser.add_argument("--export-c-array", action="store_true",
                        default=False, help="Exports a given buffer as a C array")
    parser.add_argument(
        "--c-name", help="Override C variable name on export", default=None)
    parser.add_argument(
        "--output-dir", help="Output directory for the signed data", default="./")
    parser.add_argument(
        "--additional-signers", nargs='*', help="chain the signing certificate to", default=[])

    args = parser.parse_args()

    if ',' not in args.attributes:
        logger.error("Must provide at least one of \"NV\", \"BS\" or \"RT\"")
        sys.exit(1)

    if 'AT' not in args.attributes:
        logger.error(
            "The time based authenticated variable attribute (\"AT\") must be set")
        sys.exit(1)

    # verify the attributes and calculate
    attributes_value = 0
    for a in args.attributes.split(','):
        if a not in ATTRIBUTE_MAP:
            logger.error("%s is not a valid attribute", a)
            sys.exit(1)

        attributes_value |= ATTRIBUTE_MAP[a.upper()]

    setattr(args, "attributes_value", attributes_value)

    return args


def pkcs7_sign(buffer, pfx_file, password="password", additional_certificates=False, additional_signers=[]):
    """
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs7
    """
    pkcs12_blob = b""
    # read from the pfx file the pkcs12_blob
    with open(pfx_file, 'rb') as f:
        pkcs12_blob = f.read()

    # Grab the certificate key, certificate, and the additional certificates (public keys)
    pkcs12_store = pkcs12.load_pkcs12(pkcs12_blob, password.encode('utf-8'))

    # Set the options for the pkcs7 signature:
    #   - The signature is detached
    #   - Do not convert LF to CRLF in the file (windows format)
    #   - Remove the attributes section from the pkcs7 structure
    options = [pkcs7.PKCS7Options.DetachedSignature,
               pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoAttributes]
    
    # Tbs Certificate
    # https://www.rfc-editor.org/rfc/rfc5280#section-4.1

    signature_builder = pkcs7.PKCS7SignatureBuilder()
    signature_builder = signature_builder.set_data(buffer)

    # TODO Adding mulitiple signers adds multiple tbsCertificates

    logger.info("Signing with Certificate: ")
    logger.info("\tIssuer: %s", pkcs12_store.cert.certificate.issuer)
    logger.info("\tSubject: %s", pkcs12_store.cert.certificate.subject)
    # add the signer certificate
    signature_builder = signature_builder.add_signer(pkcs12_store.cert.certificate, pkcs12_store.key, hashes.SHA256())

    if additional_certificates:
        # add the additional certificates in the pfx file
        for i, cert in enumerate(pkcs12_store.additional_certs):
            tab_indent = i + 1
            logger.info("")
            logger.info("%sAdding Additional Certificate: ", tab_indent*'\t')
            logger.info("%s\tIssuer: %s", tab_indent*'\t', cert.certificate.issuer)
            logger.info("%s\tSubject: %s", tab_indent*'\t', cert.certificate.subject)
            signature_builder = signature_builder.add_certificate(cert.certificate)
            #signature_builder = signature_builder.add_signer(cert.certificate, pkcs12_store.key, hashes.SHA256())

    for signer in additional_signers:
        pkcs12_additional_signer_blob = b""
        # read from the pfx file the pkcs12_blob
        with open(signer, 'rb') as f:
            pkcs12_additional_signer_blob = f.read()

        # Grab the certificate key, certificate, and the additional certificates (public keys)
        pkcs12_additional_signer_store = pkcs12.load_pkcs12(pkcs12_additional_signer_blob, password.encode('utf-8'))
        logger.info("Signing with Certificate: ")
        logger.info("\tIssuer: %s", pkcs12_additional_signer_store.cert.certificate.issuer)
        logger.info("\tSubject: %s", pkcs12_additional_signer_store.cert.certificate.subject)
        # add the signer certificate
        signature_builder = signature_builder.add_signer(pkcs12_additional_signer_store.cert.certificate, pkcs12_additional_signer_store.key, hashes.SHA256())

    # The signature is enclosed in a asn1 content info structure
    signature = signature_builder.sign(serialization.Encoding.DER, options)

    # lets decode the der encoded structure as an asn1Spec ContentInfo
    content_info, _ = der_decode(signature, asn1Spec=rfc2315.ContentInfo())

    # Check that this is a signed data structure (doesn't really matter)
    content_type = content_info.getComponentByName('contentType')
    if content_type != rfc2315.signedData:
        raise Exception("This wasn't a signed data structure?")

    # TODO I'm thought UEFI allowed for the signature to be in a ContentInfo Structure. Why do I have to remove it?
    signed_data, _ = der_decode(content_info.getComponentByName('content'), asn1Spec=rfc2315.SignedData())

    logger.debug(signed_data)

    return der_encode(signed_data)


# def SignData(buffer, certificate, password, trust_anchor=None):
#    """
#    Signs the data using
#    """
#    #  Write the buffer to a temporary location so we can hash it with signtool
#    with open(DATA_BUFFER_FILE, 'wb') as f:
#        f.write(buffer)

    # Use signtool to produce a digest of the variable
    # signtool sign /fd sha256 /p7ce DetachedSignedData /p7co 1.2.840.113549.1.7.2 /p7 "C:\\" /f "Cert.pfx" /p password /debug /v "data.bin"
#    out = DetachedSignWithSignTool(signtoolpath,
#                                   DATA_BUFFER_FILE,
#                                   SIGNATURE_BUFFER_FILE,
#                                   certificate,
#                                   password,
#                                   AutoSelect=True,
#                                   AdditionalCertificate=trust_anchor)
#    if out != 0:
#        logger.error("Signtool Failed")
#        return None

#    signature = ""
#    with open(SIGNATURE_BUFFER_FILE, 'rb') as f:
#        signature = f.read()

#    return signature


class V2AuthenticatedVariable(object):

    def __init__(self, decodefs=None):

        # The signature buffer is what is is used for "signing the payload"
        self.signature_buffer = None
        self.variable_data = b""
        self.efi_time = b""
        self.signature = b""

    def new(self, name, guid, attributes, tm=time.localtime(), variablefs=None):
        """
        :param variablefs: must be opened as 'rb'
        """

        self.efi_time = struct.pack(
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
        self.signature_buffer = name.encode('utf_16_le') + guid.bytes_le + \
            struct.pack('<I', attributes) + self.efi_time

        # Filestream may be empty (delete variable)
        if variablefs:
            self.variable_data = variablefs.read()

        # Append the variable data to the buffer
        self.signature_buffer += self.variable_data

    def sign_payload(self, certificate, password, additional_signers=[]):
        """
        :param certificate: signing certificate
        :param password: password for the signing certificate
        """

        if not self.signature_buffer:
            logger.warning("Signature Buffer was empty")
            return b""

        self.signature = pkcs7_sign(self.signature_buffer, certificate, password, additional_signers=additional_signers)

        return self.signature

    def _deserialize(self, fs):
        raise Exception("Not Implemented")

    def serialize(self):
        """
        returns byte array of serialized buffer
        """

        if not self.signature:
            logger.error("Can't serialize without a signature")
            return b""

        # Set the wincert and authinfo
        wincert = struct.pack(WINCERT_FMT,
                              WINCERT_FMT_SIZE + len(self.signature),
                              WIN_CERT_REVISION_2_0,
                              WIN_CERT_TYPE_EFI_GUID,
                              uuid.UUID(EFI_CERT_TYPE_PKCS7_GUID).bytes_le)

        return self.efi_time + wincert + self.signature + self.variable_data

    def get_signature(self):
        return self.signature


def create_authenticated_variable_v2(tm, name, guid, attributes, data_file, certificate, cert_password, output_dir, additional_signers):
    """
    :param tm: Time object representing the time at which this variable was created
    :param name: UEFI variable name
    :param guid: The GUID namespace that the variable belongs to
    :param attributes: The attributes the variable 
    :param data_file: The filename containing the binary data to be serialized, hashed and converted into an
         authenticated variable (May be an empty file)
    :param certificate: the certificate to sign the binary data with (May be PKCS7 or PFX)
    :param cert_password: the password for the certificate
    :param output_dir: directory to drop the signed authenticated variable data
    """

    v2_auth_var = V2AuthenticatedVariable()

    # TODO: V2 is the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS and we should choose the correct variable based on that
    # Create a new private authenticated variable

    with open(data_file, 'rb') as f:
        v2_auth_var.new(name, guid, attributes, tm=tm, variablefs=f)

    signature = v2_auth_var.sign_payload(
        certificate, cert_password, additional_signers)
    if not signature:
        logger.error("Signature Failed")
        return

    serialized_variable = v2_auth_var.serialize()
    if not serialized_variable:
        logger.error("Invalid serialized variable")
        return

    output_file = data_file + ".signature"
    if output_dir:
        filename = os.path.split(output_file)[-1]
        output_file = os.path.join(output_dir, filename)

    with open(output_file, 'wb') as f:
        f.write(v2_auth_var.get_signature())

    # output_file = data_file + ".signature2"
    # if output_dir:
    #    filename = os.path.split(output_file)[-1]
    #    output_file = os.path.join(output_dir, filename)

    # with open(output_file, 'wb') as f:
    #    f.write(v2_auth_var.get_signature2())

    output_file = data_file + ".signed"
    if output_dir:
        filename = os.path.split(output_file)[-1]
        output_file = os.path.join(output_dir, filename)

    with open(output_file, 'wb') as f:
        f.write(serialized_variable)

    logger.info("Created %s", output_file)

    return output_file


def main():
    args = parse_args()

    # Generate a  timestamp
    tm = time.localtime()

    output_dir = args.output_dir
    if args.c_name:
        output_dir = os.path.join(output_dir, args.c_name)
        os.makedirs(output_dir, exist_ok=True)

    output_file = None

    if 'AT' in args.attributes:
        output_file = create_authenticated_variable_v2(
            tm, args.name, args.guid, args.attributes_value, args.data_file, args.certificate,
            args.cert_password, output_dir, args.additional_signers)

    if not output_file:
        logger.error("Failed to create output file")
        sys.exit(1)

    if args.export_c_array:
        export_c_array(output_file, output_dir, args.name, args.c_name)

    dest_data_file = os.path.split(args.data_file)[-1]
    dest_data_file = os.path.join(output_dir, dest_data_file)
    # Copy the original file
    shutil.copy(args.data_file, dest_data_file)

    # Success
    sys.exit(0)


main()
