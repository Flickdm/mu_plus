#Requires -RunAsAdministrator
# This script *unfortunately* requires ADMIN privileges due to New-SelfSignedCertificate

# Remove all generated certificates that are left over
$items = Get-ChildItem -Path Cert:\LocalMachine\My\ -Recurse
foreach ($item in $items) {
     if($item.Subject -like "*contoso*") {
         $item | Remove-Item -Force
     }
}

$FormatAuthVar = "./FormatAuthenticatedVariable.py"

# Have to leave this outside the globals - since it's inaccessible during construction of the hashtable
$Password = "password"

# Global Variables used throughout the script
$Globals = @{
    # Windows Certificate Location
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
}


# Folder Structure Layout
$DataFolder = "./Data"
$CertName = "Certs"
$CertificateFolder = "$DataFolder/$CertName"
$TestDataName = "TestData"
$TestDataFolder = "$DataFolder/$TestDataName"

$OutputFolder = "./Output"

# Clean up from a pervious run
Remove-Item $DataFolder -Recurse -Force -Confirm:$false
New-Item -Path $DataFolder -ItemType Directory
New-Item -Path $CertificateFolder -ItemType Directory
New-Item -Path $TestDataFolder -ItemType Directory

Remove-Item $OutputFolder -Recurse -Force -Confirm:$false
New-Item -Path $OutputFolder -ItemType Directory


function GenerateCertificate {
    <#
    This function generates a certificate used for mock testing
    #>

    param (
        $KeyLength,
        $CommonName,
        $VariableName,
        $VariablePrefix,
        $Signer
    )
    
    # Return object on success
    $PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"

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
    $SignedCertificateParams = @{
        DnsName = "www.${Globals.Certificate.Organization}.com"
        CertStoreLocation = $Globals.Certificate.Store
        KeyAlgorithm = "RSA"
        KeyLength = $KeyLength
        Subject = "CN=$CommonName O=${Globals.Certificate.Organization}"
        NotAfter = (Get-Date).AddYears($Globals.Certificate.LifeYears)
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=16")
    }

    if (!$Signer) {
        # If there is no signer, than this is to be treated as a Self Signed CA
        $SignedCertificateParams.TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=1")
        $SignedCertificateParams.KeyUsage = @("CertSign", "CRLSign", "DigitalSignature")
    }

    # Generate the new certifcate with the chosen params
    $Output = New-SelfSignedCertificate @SignedCertificateParams
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    # The path of the certificate in the store
    $MockCert = $Globals.Certificate.Store + $Output.Thumbprint
    
    # export the cetificate as a PFX
    Export-PfxCertificate -Cert $MockCert -FilePath $PfxCertFilePath -Password $Globals.Certificate.SecurePassword
    if ($LASTEXITCODE -ne 0) {
        return $null
    }  

    return $PfxCertFilePath
}

function GenerateTestData {
    param (
        [String]$VariableName,
        [String]$VariablePrefix,
        [String]$CommonName,
        $PfxCertFilePath
    )


    $TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}.bin"
    $EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

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

    Write-Host ">>>> $PfxCertFilePath "  $PfxCertFilePath.GetType()
    Write-Host ($PfxCertFilePath | Format-List | Out-String)

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


$CertFilePath = GenerateCertificate 2048 "2k MockPlatformKey" "MockPK" $null
$CertFilePath = $CertFilePath.value
#Write-Host ">>>>>>> " $CertFilePath $CertFilePath.GetType()
#Write-Host ($CertFilePath | Format-List | Out-String)
Write-Host $CertFilePath
#$ret = GenerateTestData "MockPK" "m2k" "2k Mock Platform Key" $CertFilePath


# Uncomment if you need a cert - this will not keep the entire certificate chain - only the selected certificate
# Export-Certificate -Cert $MockPKCert -FilePath  $CertFilePath

Exit

# =============================================================================
# 2k Keys
# =============================================================================
# Key Length
$KeyLength = 2048
$VariablePrefix = "m2k"
# =============================================================================
# Generates a self signed platform key
# =============================================================================
$CommonName= "2k Mock Platform Key"
$VariableName = "MockPK"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -KeyUsage CertSign,CRLSign,DigitalSignature `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=1")

$2kMockPKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $2kMockPKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $2kMockPKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "2k Mock Key Exchange Key"
$VariableName = "MockKEK"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $2kMockPKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")
            #-KeySpec KeyExchange

$2kMockKEKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $2kMockKEKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $2kMockKEKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "2k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $2kMockKEKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")

$2kMockLeafCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $2kMockLeafCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $2kMockLeafCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}


# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================


$DestinationFolder = Join-Path -Path $OutputFolder -ChildPath "${VariablePrefix}${TestDataName}"
New-Item -Path $DestinationFolder -ItemType Directory

$OutputCertPath = Join-Path -Path $DestinationFolder -ChildPath "$CertName"
$OutputTestDataPath = Join-Path -Path $DestinationFolder -ChildPath "$TestDataName"
New-Item -Path $OutputCertPath -ItemType Directory
New-Item -Path $OutputTestDataPath -ItemType Directory

Get-ChildItem -Path $CertificateFolder -Recurse -File | Move-Item -Destination $OutputCertPath
Get-ChildItem -Path $TestDataFolder -Recurse -File | Move-Item -Destination $OutputTestDataPath


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

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -KeyUsage CertSign,CRLSign,DigitalSignature `
            -Signer $2kMockPKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=1")

$3kMockPKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $3kMockPKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $3kMockPKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}


# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "3k Mock Key Exchange Key"
$VariableName = "MockKEK"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $3kMockPKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")
            #-KeySpec KeyExchange

$3kMockKEKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $3kMockKEKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $3kMockKEKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "3k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $3kMockKEKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")

$3kMockLeafCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $3kMockLeafCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $3kMockLeafCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================


$DestinationFolder = Join-Path -Path $OutputFolder -ChildPath "${VariablePrefix}${TestDataName}"
New-Item -Path $DestinationFolder -ItemType Directory

$OutputCertPath = Join-Path -Path $DestinationFolder -ChildPath "$CertName"
$OutputTestDataPath = Join-Path -Path $DestinationFolder -ChildPath "$TestDataName"
New-Item -Path $OutputCertPath -ItemType Directory
New-Item -Path $OutputTestDataPath -ItemType Directory

Get-ChildItem -Path $CertificateFolder -Recurse -File | Move-Item -Destination $OutputCertPath
Get-ChildItem -Path $TestDataFolder -Recurse -File | Move-Item -Destination $OutputTestDataPath


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

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -KeyUsage CertSign,CRLSign,DigitalSignature `
            -Signer $3kMockPKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=1")

$4kMockPKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $4kMockPKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $4kMockPKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# =============================================================================
# Generates a Intermediate Cert (Key Exchange Key) signed by the Mock PK
# =============================================================================
$CommonName= "4k Mock Key Exchange Key"
$VariableName = "MockKEK"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $4kMockPKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")
            #-KeySpec KeyExchange

$4kMockKEKCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $4kMockKEKCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $4kMockKEKCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}


# =============================================================================
# Generates a Leaf Certificate signed by the Mock KEK
# =============================================================================
$CommonName= "4k Mock Leaf Certficate"
$VariableName = "MockLeaf"

$PfxCertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.pfx"
$CertFilePath = Join-Path -Path $CertificateFolder -ChildPath "$VariableName.cer"
$TestDataPath = Join-Path -Path $TestDataFolder -ChildPath "$VariableName.bin"
$EmptyTestDataPath = Join-Path -Path $TestDataFolder -ChildPath "${VariableName}Empty.bin"

New-Item -Name $EmptyTestDataPath -ItemType File
"$VariableDataFormat $CommonName" | Out-File -Encoding Ascii -FilePath $TestDataPath

$Output = New-SelfSignedCertificate `
            -DnsName "www.$Organization.com" `
            -CertStoreLocation $CertificateStore `
            -KeyAlgorithm RSA `
            -KeyLength $KeyLength `
            -Subject "CN=$CommonName O=$Organization" `
            -NotAfter (Get-Date).AddYears(10) `
            -Signer $4kMockKEKCert `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}CA=0&pathlength=0")

$4kMockLeafCert = $CertificateStore + $Output.Thumbprint
Export-Certificate -Cert $4kMockLeafCert -FilePath  $CertFilePath
Export-PfxCertificate -Cert $4kMockLeafCert -FilePath $PfxCertFilePath -Password $SecureCertificatePassword

# Generate the data authenticated variable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $TestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}"
if ($LASTEXITCODE -ne 0) {
    Exit
}

# Generate the empty authenticated vatriable
python FormatAuthenticatedVariable.py $VariableName $VariableGuid $Attributes $EmptyTestDataPath $PfxCertFilePath --cert-password $CertificatePassword --export-c-array --c-name "${VariablePrefix}${VariableName}Delete"
if ($LASTEXITCODE -ne 0) {
    Exit
}


# =============================================================================
# Clean up and move the files to their final destination
# =============================================================================


$DestinationFolder = Join-Path -Path $OutputFolder -ChildPath "${VariablePrefix}${TestDataName}"
New-Item -Path $DestinationFolder -ItemType Directory

$OutputCertPath = Join-Path -Path $DestinationFolder -ChildPath "$CertName"
$OutputTestDataPath = Join-Path -Path $DestinationFolder -ChildPath "$TestDataName"
New-Item -Path $OutputCertPath -ItemType Directory
New-Item -Path $OutputTestDataPath -ItemType Directory

Get-ChildItem -Path $CertificateFolder -Recurse -File | Move-Item -Destination $OutputCertPath
Get-ChildItem -Path $TestDataFolder -Recurse -File | Move-Item -Destination $OutputTestDataPath


# =============================================================================
# delete the certs from the keystore
# =============================================================================

del $2kMockPKCert
del $2kMockKEKCert 
del $2kMockLeafCert

del $3kMockPKCert
del $3kMockKEKCert
del $3kMockLeafCert

del $4kMockPKCert
del $4kMockKEKCert
del $4kMockLeafCert

$OutFile = Join-Path -Path $OutputFolder -ChildPath "Exported.c"

Get-ChildItem $OutputFolder -Filter '*.c' -Recurse `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'c'} `
 | Foreach-Object {
    cat $_.FullName | Add-Content -Path $OutFile 
}

$OutFile = Join-Path -Path $OutputFolder -ChildPath "Exported.h"

Get-ChildItem $OutputFolder -Filter '*.h' -Recurse `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'h'} `
 | Foreach-Object {
    cat $_.FullName | Add-Content -Path $OutFile 
}