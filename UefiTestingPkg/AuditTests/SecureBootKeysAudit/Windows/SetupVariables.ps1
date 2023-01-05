#Requires -RunAsAdministrator
# This script *unfortunately* requires ADMIN privileges due to New-SelfSignedCertificate

# Clear LASTEXITCODE
$LASTEXITCODE = 0

# This script relies on this script to format and sign Authenticated
$FormatAuthVar = "./FormatAuthenticatedVariable.py"

# Have to leave this outside the globals - since it's inaccessible during initialization of the hashtable
$Password = "password"
$DataFolder = "./Data"
$TestDataName = "TestData"
$CertName = "Certs"

# Global Variables used throughout the script
$Globals = @{
    Certificate = @{
        Store = "Cert:\LocalMachine\My\"
        Organization = "contoso"
        Password = $Password
        SecurePassword = ConvertTo-SecureString $Password -Force -AsPlainText
        LifeYears = 10 # How long in the future should the Certificate be valid
    }
    Variable = @{
        Attributes = "NV,BS,RT,AT"
        Guid = "b3f4fb27-f382-4484-9b77-226b2b4348bb"
        Format = "Hello "
    }
    Layout = @{
        DataFolder = $DataFolder
        CertName = $CertName 
        CertificateFolder = "$DataFolder/$CertName"
        TestDataName = $TestDataName
        TestDataFolder = "$DataFolder/$TestDataName"
    }
}

# Clean up from a pervious run
Remove-Item $Globals.Layout.DataFolder -Recurse -Force -Confirm:$false
New-Item -Path $Globals.Layout.DataFolder -ItemType Directory
New-Item -Path $Globals.Layout.CertificateFolder -ItemType Directory
New-Item -Path $Globals.Layout.TestDataFolder -ItemType Directory

function GenerateCertificate {
    <#
    This function generates a certificate used for mock testing
    
    :param KeyLength: The size in bits of the length of the key (ex 2048)
    :param CommonName: Common name field of the certificate
    :param Variable Name: Name of the variable (Not important for the certificate but used to track which pfx is tied to which signed data)
    :param VariablePrefix: Prefix to append to the beginning of the certificate for tracking (Not Important)
    :param Signer: Signing certificate object from the Certificate Store
    
    :return: HashTable Object
        {
            .Cert     # Path to Certificate in the Certificate Store 
            .CertPath # Path to the pfx file generated
        }
    #>

    param (
        $KeyLength,
        $CommonName,
        $VariableName,
        $VariablePrefix,
        $Signer
    )
    
    # Return object on success
    $PfxCertFilePath = Join-Path -Path $Globals.Layout.CertificateFolder -ChildPath "${VariablePrefix}${VariableName}.pfx"

    # Text Extensions:
    # Code Signing: 2.5.29.37={text}1.3.6.1.5.5.7.3.3
    # Constraint: 2.5.29.19={text}CA=0 (NOT CA) 2.5.29.19={text}CA=1 (CA)
    # Pathlength: pathlength=16 
    #       Arbitrarily long path length, essentially this the length of valid intermediate CA's before an End Entity
    #       so CA -> 1 ... 2  -> EE - Valid
    #          CA -> 1 ... 16 -> EE - Valid
    #          CA -> 1 ... 17 -> EE - Invalid
    #       A pathlength set too short will not be valid when checked by a validity engine

    # Set the options that are required for signing
    $Organization = $Globals.Certificate.Organization

    $SignedCertificateParams = @{
        DnsName = "www.$Organization.com"
        CertStoreLocation = $Globals.Certificate.Store
        KeyAlgorithm = "RSA"
        KeyLength = $KeyLength
        Subject = "CN=$CommonName O=$Organization"
        NotAfter = (Get-Date).AddYears($Globals.Certificate.LifeYears)
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=1")
        KeyUsage = @("CertSign", "CRLSign", "DigitalSignature")
    }

    if ($Signer) {
        $SignedCertificateParams["TextExtension"] = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=16")
        $SignedCertificateParams["Signer"] = $Signer
    }

    Write-Host "> New-SelfSignedCertificate " @SignedCertificateParams

    # Generate the new certifcate with the chosen params
    $Output = New-SelfSignedCertificate @SignedCertificateParams
    if ($LASTEXITCODE -ne 0) {
        write-host $Output
        Write-Host "New-SelfSignedCertificate Failed"
        return $null
    }

    # The path of the certificate in the store
    $MockCert = $Globals.Certificate.Store + $Output.Thumbprint 
    
    # export the cetificate as a PFX
    Export-PfxCertificate -Cert $MockCert -FilePath $PfxCertFilePath -Password $Globals.Certificate.SecurePassword | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Export-PfxCertificate Failed"
        return $null
    }

    $ReturnObject = @{
        Cert = $MockCert
        CertPath = $PfxCertFilePath  
    }

    return $ReturnObject
}

function GenerateTestData {
    <#
    This function generates test data for the mock variables and then signs it with the provided certificate

    :param VariableName: UEFI Variable Name (IMPORTANT This needs to match the variable used on the device that is used for signing)
    :param VariablePrefix: Variable prefix used for tracking
    :param CommonName: Used in conjunction with Global.Variable.Format to produce content that is unique for testing
    :param PfxCertFilePath: The path to the Pfx Certificate

    :return:
        boolean true if Success, false otherwise
    #>

    param (
        [String]$VariableName,
        [String]$VariablePrefix,
        [String]$CommonName,
        [String]$PfxCertFilePath
    )

    $TestDataPath = Join-Path -Path $Globals.Layout.TestDataFolder -ChildPath "${VariableName}.bin"
    $EmptyTestDataPath = Join-Path -Path  $Globals.Layout.TestDataFolder -ChildPath "${VariableName}Empty.bin"

    # Create the empty file
    New-Item -Name ${EmptyTestDataPath} -ItemType File
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    # Create the File with test data that is unique to the variable signing it
    "${Variable.Format} $CommonName" | Out-File -Encoding Ascii -FilePath ${TestDataPath}
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    # Generate the data authenticated variable
    python $FormatAuthVar $VariableName $Globals.Variable.Guid $Globals.Variable.Attributes $TestDataPath `
        $PfxCertFilePath --cert-password $Globals.Certificate.Password --export-c-array --c-name "${VariablePrefix}${VariableName}"
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    # Generate the empty authenticated vatriable
    python $FormatAuthVar $VariableName $Globals.Variable.Guid $Globals.Variable.Attributes $EmptyTestDataPath `
        $PfxCertFilePath --cert-password $Globals.Certificate.Password --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return $true
}

function CopyDataToFinalDestination {
    <#
    Copies the data to the final destination

    :param VariablePrefix: Variable prefix used for labeling which variables and certificates are in the folder

    :return: None
    #>

    Param (
        $VariablePrefix
    )

    $TestDataName = $Globals.Layout.TestDataName
    $DestinationFolder = Join-Path -Path $Globals.Layout.DataFolder -ChildPath "${VariablePrefix}${TestDataName}"
    New-Item -Path $DestinationFolder -ItemType Directory

    $OutputCertPath = Join-Path -Path $DestinationFolder -ChildPath $Globals.Layout.CertName
    $OutputTestDataPath = Join-Path -Path $DestinationFolder -ChildPath $Globals.Layout.TestDataName
    New-Item -Path $OutputCertPath -ItemType Directory
    New-Item -Path $OutputTestDataPath -ItemType Directory

    Get-ChildItem -Path $Globals.Layout.CertificateFolder -Recurse -File | Move-Item -Destination $OutputCertPath
    Get-ChildItem -Path $Globals.Layout.TestDataFolder  -Recurse -File | Move-Item -Destination $OutputTestDataPath
}


# =============================================================================
# 2k Keys
# =============================================================================
$KeyLength = 2048
$VariablePrefix = "m2k"
# =============================================================================
# Generates a Platform Key CA (PK) self signed
# =============================================================================
$CommonName= "2k Mock Platform Key"
$VariableName = "MockPK"

$2KMockPK = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $null
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $2KMockPK.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "2k Mock Key Exchange Key"
$VariableName = "MockKEK"

$2KMockKek = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $2KMockPK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $2KMockKek.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "2k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$2KMockLC = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $2KMockKEK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $2KMockLC.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================
CopyDataToFinalDestination $VariablePrefix

# =============================================================================
# 3k Keys
# =============================================================================
# Key Length
$KeyLength = 3072
$VariablePrefix = "m3k"
# =============================================================================
# Generates a self signed platform key
# =============================================================================
$CommonName= "3k Mock Platform Key"
$VariableName = "MockPK"

$3KMockPK = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $2KMockPK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $3KMockPK.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "3k Mock Key Exchange Key"
$VariableName = "MockKEK"

$3KMockKEK = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $3KMockPK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $3KMockKEK.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "3k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$3KMockLC = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $3KMockKEK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $3KMockLC.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================
CopyDataToFinalDestination $VariablePrefix

# =============================================================================
# 4k Keys
# =============================================================================
# Key Length
$KeyLength = 4096
$VariablePrefix = "m4k"
# =============================================================================
# Generates a self signed platform key
# =============================================================================
$CommonName= "4k Mock Platform Key"
$VariableName = "MockPK"

$4KMockPK = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $3KMockPK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $4KMockPK.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "4k Mock Key Exchange Key"
$VariableName = "MockKEK"

$4KMockKEK = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $4KMockPK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $4KMockKEK.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "4k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$4KMockLC = GenerateCertificate $KeyLength $CommonName $VariableName $VariablePrefix $4KMockKEK.Cert
$ret = GenerateTestData $VariableName $VariablePrefix $CommonName $4KMockLC.CertPath
if (!$ret) {
    Exit
}

# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================
CopyDataToFinalDestination $VariablePrefix

# =============================================================================
# delete the certs from the keystore
# =============================================================================

# Locate by organization and delete
$Organization = $Globals.Certificate.Organization
$items = Get-ChildItem -Path $Globals.Certificate.Store -Recurse
foreach ($item in $items) {
     if($item.Subject -like "*$Organization*") {
         $item | Remove-Item -Force
     }
}

Remove-Item $Globals.Layout.CertificateFolder -Recurse -Force -Confirm:$false
Remove-Item $Globals.Layout.TestDataFolder -Recurse -Force -Confirm:$false

# =============================================================================
# Copy All the C arrays and variables to their respective header and source file
# =============================================================================

$OutFile = Join-Path -Path $Globals.Layout.DataFolder -ChildPath "Exported.c"

Get-ChildItem $Globals.Layout.DataFolder -Filter '*.c' -Recurse `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'c'} `
 | Foreach-Object {
    cat $_.FullName | Add-Content -Path $OutFile 
}

$OutFile = Join-Path -Path $Globals.Layout.DataFolder -ChildPath "Exported.h"

Get-ChildItem $Globals.Layout.DataFolder -Filter '*.h' -Recurse `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'h'} `
 | Foreach-Object {
    cat $_.FullName | Add-Content -Path $OutFile 
}