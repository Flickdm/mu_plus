#Requires -RunAsAdministrator
# This script *unfortunately* requires ADMIN privileges due to New-SelfSignedCertificate

# Windows Certificate Location
$CertificateStore = "Cert:\LocalMachine\My\"

# Fordure Structure Layout
$DataFolder = "./Data"
$CertName = "Certs"
$CertificateFolder = "$DataFolder/$CertName"
$TestDataName = "TestData"
$TestDataFolder = "$DataFolder/$TestDataName"
$Organization = "contoso"

$OutputFolder = "./Output"


# Certificate Password
$CertificatePassword = "password"
$SecureCertificatePassword = ConvertTo-SecureString $CertificatePassword -Force -AsPlainText

# UEFI Variable shared data
$Attributes = "NV,BS,RT,AT"
$VariableGuid = "b3f4fb27-f382-4484-9b77-226b2b4348bb"
$VariableDataFormat = "Hello " # The name of the cert will be appended on

# Clean up from a pervious run
Remove-Item $DataFolder -Recurse -Force -Confirm:$false
New-Item -Path $DataFolder -ItemType Directory
New-Item -Path $CertificateFolder -ItemType Directory
New-Item -Path $TestDataFolder -ItemType Directory

Remove-Item $OutputFolder -Recurse -Force -Confirm:$false
New-Item -Path $OutputFolder -ItemType Directory

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