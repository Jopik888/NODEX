$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$DesktopRoot = Split-Path -Parent $PSScriptRoot
$Assets = Join-Path $DesktopRoot 'assets'
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("nodex-runtime-" + [guid]::NewGuid().ToString('N'))
$NodeVersion = '24.22.3'
$PostgresVersion = '17.11'
$KuboVersion = '0.43.1'
$PostgresUrl = 'https://sbp.enterprisedb.com/getfile.jsp?fileid=1260569'
$PostgresSha256Expected = 'b9424ee7bc60b52450ff910a3630225df32e633f3cb29c1d126d9299d59aea28'
$NodeBase = "https://nodejs.org/dist/v$NodeVersion"
$NodeZipName = "node-v$NodeVersion-win-x64.zip"
$KuboBase = "https://dist.ipfs.tech/kubo/v$KuboVersion"
$KuboZipName = "kubo_v$($KuboVersion)_windows-amd64.zip"

function Get-Download([string]$Url, [string]$Destination) {
  Write-Host "Downloading $Url"
  Invoke-WebRequest -Uri $Url -OutFile $Destination -MaximumRedirection 10
  if (!(Test-Path -LiteralPath $Destination) -or (Get-Item -LiteralPath $Destination).Length -lt 1) {
    throw "Download is missing or empty: $Destination"
  }
}

function Get-Sha256([string]$File) {
  (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Expand-CheckedZip([string]$Archive, [string]$Destination) {
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Expand-Archive -LiteralPath $Archive -DestinationPath $Destination -Force
}

New-Item -ItemType Directory -Force -Path $Temp | Out-Null
try {
  foreach ($folder in @('runtime', 'postgres', 'ipfs')) {
    $target = Join-Path $Assets $folder
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
  }

  # Node.js release signature and archive checksum.
  $NodeZip = Join-Path $Temp $NodeZipName
  $NodeSig = Join-Path $Temp 'SHASUMS256.txt.asc'
  $NodeVerifiedSums = Join-Path $Temp 'SHASUMS256.verified.txt'
  $NodeKeyring = Join-Path $Temp 'nodejs-active-release-keys.kbx'
  $NodeReleaseKeyFingerprint = '5BE8A3F6C8A5C01D106C0AD820B1A390B168D356'
  Get-Download "$NodeBase/$NodeZipName" $NodeZip
  Get-Download "$NodeBase/SHASUMS256.txt.asc" $NodeSig
  Get-Download 'https://raw.githubusercontent.com/nodejs/release-keys/481637f813e912c4aa3622d7964ab426c97b8e8d/gpg-only-active-keys/pubring.kbx' $NodeKeyring

  # Prefer the native Windows GnuPG binary. Git for Windows ships an MSYS gpgv
  # whose path translation can corrupt Windows absolute keyring paths.
  $GpgvCandidates = @(
    'C:\Program Files (x86)\GnuPG\bin\gpgv.exe',
    'C:\Program Files\GnuPG\bin\gpgv.exe'
  )
  $GpgvPath = $GpgvCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (!$GpgvPath) {
    choco install gnupg --version=2.5.21 -y --no-progress
    $GpgvPath = $GpgvCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  }
  if (!$GpgvPath) { throw 'Native Windows GnuPG gpgv.exe could not be located after installation.' }

  # Node.js documents a clear-signed .asc file on stdin; use byte-preserving
  # stdin with the native Windows GnuPG executable and an explicit keyring.
  $GpgStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $GpgStartInfo.FileName = $GpgvPath
  $GpgStartInfo.UseShellExecute = $false
  $GpgStartInfo.CreateNoWindow = $true
  $GpgStartInfo.RedirectStandardInput = $true
  $GpgStartInfo.RedirectStandardError = $true
  $GpgStartInfo.RedirectStandardOutput = $true
  $GpgStartInfo.ArgumentList.Add('--status-fd=1')
  $GpgStartInfo.ArgumentList.Add("--keyring=$NodeKeyring")
  $GpgStartInfo.ArgumentList.Add("--output=$NodeVerifiedSums")

  $GpgProcess = [System.Diagnostics.Process]::new()
  $GpgProcess.StartInfo = $GpgStartInfo
  if (!$GpgProcess.Start()) { throw 'Unable to start native Windows GnuPG verifier.' }
  try {
    $SignatureBytes = [IO.File]::ReadAllBytes($NodeSig)
    $GpgProcess.StandardInput.BaseStream.Write($SignatureBytes, 0, $SignatureBytes.Length)
    $GpgProcess.StandardInput.Close()
    $GpgProcess.WaitForExit()
    $GpgStdout = $GpgProcess.StandardOutput.ReadToEnd()
    $GpgStderr = $GpgProcess.StandardError.ReadToEnd()
    if ($GpgProcess.ExitCode -ne 0 -or !(Test-Path -LiteralPath $NodeVerifiedSums)) {
      throw "Node.js SHASUMS256.txt.asc signature verification failed: $GpgStderr"
    }
    if ($GpgStdout -notmatch ('(?m)^\[GNUPG:\] VALIDSIG ' + $NodeReleaseKeyFingerprint + '(?:\s|$)')) {
      throw "Node.js SHASUMS signature is valid but was not signed by the pinned release key $NodeReleaseKeyFingerprint. GPG status: $GpgStdout"
    }
  } finally {
    $GpgProcess.Dispose()
  }

  $NodeSumLine = Get-Content -LiteralPath $NodeVerifiedSums |
    Where-Object { $_.EndsWith($NodeZipName, [StringComparison]::Ordinal) } |
    Select-Object -First 1
  if (!$NodeSumLine) { throw 'The signed Node.js SHASUMS file does not list the pinned Windows x64 ZIP.' }
  $NodeExpected = ($NodeSumLine -split '\s+')[0].ToLowerInvariant()
  if ($NodeExpected -notmatch '^[a-f0-9]{64}$') { throw 'The Node.js ZIP checksum entry is malformed.' }
  $NodeActual = Get-Sha256 $NodeZip
  if ($NodeActual -ne $NodeExpected) { throw "Node.js ZIP SHA-256 mismatch: expected $NodeExpected, got $NodeActual" }

  $NodeExtract = Join-Path $Temp 'node-extract'
  Expand-CheckedZip $NodeZip $NodeExtract
  $NodeExe = Get-ChildItem -LiteralPath $NodeExtract -Filter node.exe -Recurse | Select-Object -First 1
  if (!$NodeExe) { throw 'node.exe was not found in the verified Node.js archive.' }
  Copy-Item -LiteralPath $NodeExe.FullName -Destination (Join-Path $Assets 'runtime/node.exe')
  $NodeLicense = Get-ChildItem -LiteralPath $NodeExtract -Filter LICENSE -Recurse | Select-Object -First 1
  if ($NodeLicense) { Copy-Item -LiteralPath $NodeLicense.FullName -Destination (Join-Path $Assets 'runtime/LICENSE') }
  $NodeExeHash = Get-Sha256 (Join-Path $Assets 'runtime/node.exe')

  # PostgreSQL 17.11-4 portable binaries ZIP, pinned to EDB's published digest.
  $PostgresZip = Join-Path $Temp 'postgresql-17.11-4-windows-x64-binaries.zip'
  Get-Download $PostgresUrl $PostgresZip
  $PostgresActual = Get-Sha256 $PostgresZip
  if ($PostgresActual -ne $PostgresSha256Expected) {
    throw "EDB PostgreSQL archive SHA-256 mismatch: expected $PostgresSha256Expected, got $PostgresActual"
  }
  $PostgresExtract = Join-Path $Temp 'postgres-extract'
  Expand-CheckedZip $PostgresZip $PostgresExtract
  $PostgresExe = Get-ChildItem -LiteralPath $PostgresExtract -Filter postgres.exe -Recurse |
    Where-Object { $_.Directory.Name -eq 'bin' } | Select-Object -First 1
  if (!$PostgresExe) { throw 'postgres.exe was not found in the verified EDB archive.' }
  $PostgresRoot = $PostgresExe.Directory.Parent.FullName
  foreach ($required in @('bin', 'lib', 'share')) {
    if (!(Test-Path -LiteralPath (Join-Path $PostgresRoot $required))) {
      throw "EDB archive is missing required PostgreSQL folder: $required"
    }
  }
  Copy-Item -Path (Join-Path $PostgresRoot '*') -Destination (Join-Path $Assets 'postgres') -Recurse -Force
  $PostgresExeHash = Get-Sha256 (Join-Path $Assets 'postgres/bin/postgres.exe')

  $PgPeFiles = @(Get-ChildItem -LiteralPath @((Join-Path $Assets 'postgres/bin'), (Join-Path $Assets 'postgres/lib')) -Recurse -File |
    Where-Object { $_.Extension -in '.exe', '.dll' })
  if ($PgPeFiles.Count -eq 0) { throw 'No PostgreSQL EXE/DLL files were found for signature inspection.' }
  $PgSignatureStatuses = @($PgPeFiles | ForEach-Object {
    [string](Get-AuthenticodeSignature -LiteralPath $_.FullName).Status
  } | Sort-Object -Unique)
  $PgInvalid = @($PgSignatureStatuses | Where-Object { $_ -notin @('Valid', 'NotSigned') })
  if ($PgInvalid.Count -gt 0) { throw "EDB PostgreSQL binaries have invalid/untrusted signatures: $($PgInvalid -join ', ')" }
  if ($PgSignatureStatuses -contains 'NotSigned') {
    $PostgresSignatureState = 'NOT_SIGNED_INTERNAL_ALPHA'
    Write-Warning 'EDB PostgreSQL contains unsigned PE files. This package is closed-Alpha only; Windows Smart App Control may block PostgreSQL binaries.'
  } else {
    $PostgresSignatureState = 'VERIFIED'
  }

  # Kubo archive verified against the official dist.ipfs.tech SHA-512 sidecar.
  $KuboZip = Join-Path $Temp $KuboZipName
  $KuboSidecar = Join-Path $Temp "$KuboZipName.sha512"
  Get-Download "$KuboBase/$KuboZipName" $KuboZip
  Get-Download "$KuboBase/$KuboZipName.sha512" $KuboSidecar
  $KuboSidecarText = (Get-Content -LiteralPath $KuboSidecar -Raw).Trim()
  if ($KuboSidecarText -notmatch '(?<hash>[a-fA-F0-9]{128})') { throw 'Official Kubo SHA-512 sidecar is malformed.' }
  $KuboExpectedSha512 = $Matches.hash.ToLowerInvariant()
  $KuboActualSha512 = (Get-FileHash -LiteralPath $KuboZip -Algorithm SHA512).Hash.ToLowerInvariant()
  if ($KuboActualSha512 -ne $KuboExpectedSha512) {
    throw "Kubo ZIP SHA-512 mismatch: expected $KuboExpectedSha512, got $KuboActualSha512"
  }
  $KuboExtract = Join-Path $Temp 'kubo-extract'
  Expand-CheckedZip $KuboZip $KuboExtract
  $KuboExe = Get-ChildItem -LiteralPath $KuboExtract -Filter ipfs.exe -Recurse | Select-Object -First 1
  if (!$KuboExe) { throw 'ipfs.exe was not found in the verified Kubo archive.' }
  Copy-Item -LiteralPath $KuboExe.FullName -Destination (Join-Path $Assets 'ipfs/ipfs.exe')
  $KuboRoot = $KuboExe.Directory.FullName
  foreach ($license in @('LICENSE', 'LICENSE-APACHE', 'LICENSE-MIT', 'README.md')) {
    $licensePath = Join-Path $KuboRoot $license
    if (Test-Path -LiteralPath $licensePath) {
      Copy-Item -LiteralPath $licensePath -Destination (Join-Path $Assets "ipfs/$license")
    }
  }
  $KuboExeHash = Get-Sha256 (Join-Path $Assets 'ipfs/ipfs.exe')

  $NodeVersionOutput = (& (Join-Path $Assets 'runtime/node.exe') --version | Out-String).Trim()
  $PostgresVersionOutput = (& (Join-Path $Assets 'postgres/bin/postgres.exe') --version | Out-String).Trim()
  $KuboVersionOutput = (& (Join-Path $Assets 'ipfs/ipfs.exe') --version | Out-String).Trim()
  if ($NodeVersionOutput -ne "v$NodeVersion") { throw "Unexpected Node.js version: $NodeVersionOutput" }
  if ($PostgresVersionOutput -ne "postgres (PostgreSQL) $PostgresVersion") { throw "Unexpected PostgreSQL version: $PostgresVersionOutput" }
  if ($KuboVersionOutput -ne "ipfs version $KuboVersion") { throw "Unexpected Kubo version: $KuboVersionOutput" }

  $Manifest = [ordered]@{
    schemaVersion = 1
    platform = 'win32-x64'
    releaseChannel = 'closed-alpha'
    installerSigning = 'unsigned'
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    components = [ordered]@{
      node = [ordered]@{ version = $NodeVersion; source = "$NodeBase/$NodeZipName"; archiveFile = $NodeZipName; file = 'runtime/node.exe'; sha256 = $NodeExeHash }
      postgres = [ordered]@{ version = $PostgresVersion; source = $PostgresUrl; archiveFile = 'postgresql-17.11-4-windows-x64-binaries.zip'; file = 'postgres/bin/postgres.exe'; sha256 = $PostgresExeHash }
      kubo = [ordered]@{ version = $KuboVersion; source = "$KuboBase/$KuboZipName"; archiveFile = $KuboZipName; file = 'ipfs/ipfs.exe'; sha256 = $KuboExeHash }
    }
    archiveSha256 = [ordered]@{
      nodeWindowsZip = $NodeActual
      postgresBinariesZip = $PostgresActual
      kuboWindowsZip = (Get-Sha256 $KuboZip)
    }
    integrityVerification = [ordered]@{
      nodeShasumsSignature = 'VERIFIED'
      postgresArchiveSha256 = 'VERIFIED'
      postgresAuthenticode = $PostgresSignatureState
      kuboArchiveSha256 = 'VERIFIED'
    }
    licenseFiles = @('runtime/LICENSE', 'ipfs/LICENSE', 'ipfs/LICENSE-APACHE', 'ipfs/LICENSE-MIT', 'postgres/')
  }
  $ManifestPath = Join-Path $Assets 'RUNTIME-MANIFEST.json'
  [IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
  Write-Host 'Runtime staging completed. Verified archives, signatures, executable hashes and exact versions.'
  Write-Host "Node.js executable SHA-256: $NodeExeHash"
  Write-Host "PostgreSQL executable SHA-256: $PostgresExeHash"
  Write-Host "Kubo executable SHA-256: $KuboExeHash"
  Write-Host "PostgreSQL Authenticode state: $PostgresSignatureState"
}
finally {
  if (Test-Path -LiteralPath $Temp) {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
