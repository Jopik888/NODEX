$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$DesktopRoot = Split-Path -Parent $PSScriptRoot
$Assets = Join-Path $DesktopRoot 'assets'
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("nodex-runtime-" + [guid]::NewGuid().ToString('N'))
$NodeVersion = '24.22.3'
$NodeZipSha256Expected = 'e612af99f626ab415ea225af6bce5c971feb448cb5cae250bb1c3fa50c5f7d9f'
$NodeExeSha256Expected = '86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6'
$PostgresVersion = '17.11'
$KuboVersion = '0.43.1'
$KuboZipSha256Expected = 'c25871516dec4d97ce1d160a26c1e3fdad294cb0eea065c0c0343bcfca86c524'
$KuboSidecarSha256Expected = '99ded6a03faa39a92417f15781da332b8ed014840e089cca354cea347ce40717'
$PostgresArchiveName = 'postgresql-17.11-5-windows-x64-binaries.zip'
$PostgresUrl = "https://get.enterprisedb.com/postgresql/$PostgresArchiveName"
$PostgresSha256Url = "$PostgresUrl.sha256"
$PostgresSha256Expected = '80379b2c04d51c30225532e0ae04509899141e9957ed096fe749d7fd9df8f82f'
$NodeBase = "https://nodejs.org/dist/v$NodeVersion"
$NodeZipName = "node-v$NodeVersion-win-x64.zip"
$KuboBase = "https://github.com/ipfs/kubo/releases/download/v$KuboVersion"
$KuboZipName = "kubo_v$($KuboVersion)_windows-amd64.zip"

function Get-Download([string]$Url, [string]$Destination) {
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  Write-Host "Downloading $Url"
  $curl = Get-Command curl.exe -ErrorAction Stop
  & $curl.Source --fail --silent --show-error --location --retry 3 --retry-all-errors --connect-timeout 30 --max-time 1800 --output $Destination $Url
  if ($LASTEXITCODE -ne 0) {
    throw "Download failed with curl exit code ${LASTEXITCODE}: $Url"
  }
  if (!(Test-Path -LiteralPath $Destination) -or (Get-Item -LiteralPath $Destination).Length -lt 1) {
    throw "Download is missing or empty: $Destination"
  }
  $watch.Stop()
  $file = Get-Item -LiteralPath $Destination
  Write-Host ("Downloaded {0:N0} bytes in {1:N1}s: {2}" -f $file.Length, $watch.Elapsed.TotalSeconds, $Destination)
}

function Get-Sha256([string]$File) {
  (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Expand-CheckedZip([string]$Archive, [string]$Destination) {
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $archiveInfo = Get-Item -LiteralPath $Archive
  Write-Host ("Extracting {0:N0} bytes: {1}" -f $archiveInfo.Length, $Archive)
  $tar = Get-Command tar.exe -ErrorAction Stop
  & $tar.Source -xf $Archive -C $Destination
  if ($LASTEXITCODE -ne 0) {
    throw "Windows tar failed to extract archive (exit code $LASTEXITCODE): $Archive"
  }
  $watch.Stop()
  Write-Host ("Extraction completed in {0:N1}s: {1}" -f $watch.Elapsed.TotalSeconds, $Destination)
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

  # Use the gpgv shipped with Git for Windows. Avoid a Chocolatey bootstrap:
  # its package installer can hang on hosted Windows runners. Run with a temp
  # working directory and relative paths to avoid MSYS argument path rewriting.
  $GpgvCandidates = @(
    (Join-Path $env:ProgramFiles 'Git\usr\bin\gpgv.exe'),
    (Join-Path $env:ProgramFiles 'Git\mingw64\bin\gpgv.exe')
  )
  $GpgvPath = $GpgvCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (!$GpgvPath) {
    $GpgvCommand = Get-Command gpgv.exe -ErrorAction SilentlyContinue
    if ($GpgvCommand) { $GpgvPath = $GpgvCommand.Source }
  }
  if (!$GpgvPath) { throw 'Git for Windows gpgv.exe could not be located. Refusing to skip Node.js release signature verification.' }

  $GpgStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $GpgStartInfo.FileName = $GpgvPath
  $GpgStartInfo.WorkingDirectory = $Temp
  $GpgStartInfo.UseShellExecute = $false
  $GpgStartInfo.CreateNoWindow = $true
  $GpgStartInfo.RedirectStandardError = $true
  $GpgStartInfo.RedirectStandardOutput = $true
  $GpgStartInfo.ArgumentList.Add('--status-fd=1')
  $GpgStartInfo.ArgumentList.Add('--homedir=.')
  $GpgStartInfo.ArgumentList.Add('--keyring=./nodejs-active-release-keys.kbx')
  $GpgStartInfo.ArgumentList.Add('--output=./SHASUMS256.verified.txt')
  $GpgStartInfo.ArgumentList.Add('./SHASUMS256.txt.asc')

  $GpgProcess = [System.Diagnostics.Process]::new()
  $GpgProcess.StartInfo = $GpgStartInfo
  if (!$GpgProcess.Start()) { throw 'Unable to start Git for Windows GnuPG verifier.' }
  try {
    $GpgStdoutTask = $GpgProcess.StandardOutput.ReadToEndAsync()
    $GpgStderrTask = $GpgProcess.StandardError.ReadToEndAsync()
    $GpgProcess.WaitForExit()
    $GpgStdout = $GpgStdoutTask.GetAwaiter().GetResult()
    $GpgStderr = $GpgStderrTask.GetAwaiter().GetResult()
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
  if ($NodeActual -ne $NodeExpected) { throw "Node.js ZIP SHA-256 mismatch against signed SHASUMS: expected $NodeExpected, got $NodeActual" }
  if ($NodeActual -ne $NodeZipSha256Expected) { throw "Node.js ZIP SHA-256 mismatch against the pinned release digest: expected $NodeZipSha256Expected, got $NodeActual" }
  Write-Host "Node.js release signature and both ZIP SHA-256 checks verified: $NodeActual"

  $NodeExtract = Join-Path $Temp 'node-extract'
  Expand-CheckedZip $NodeZip $NodeExtract
  $NodeExe = Get-ChildItem -LiteralPath $NodeExtract -Filter node.exe -Recurse | Select-Object -First 1
  if (!$NodeExe) { throw 'node.exe was not found in the verified Node.js archive.' }
  Copy-Item -LiteralPath $NodeExe.FullName -Destination (Join-Path $Assets 'runtime/node.exe')
  $NodeLicense = Get-ChildItem -LiteralPath $NodeExtract -Filter LICENSE -Recurse | Select-Object -First 1
  if ($NodeLicense) { Copy-Item -LiteralPath $NodeLicense.FullName -Destination (Join-Path $Assets 'runtime/LICENSE') }
  $NodeExeHash = Get-Sha256 (Join-Path $Assets 'runtime/node.exe')
  if ($NodeExeHash -ne $NodeExeSha256Expected) { throw "Staged Node.js executable digest mismatch: expected $NodeExeSha256Expected, got $NodeExeHash" }

  # PostgreSQL 17.11-5 portable binaries ZIP, pinned to EDB's published digest and sidecar.
  $PostgresZip = Join-Path $Temp $PostgresArchiveName
  $PostgresHashFile = Join-Path $Temp "$PostgresArchiveName.sha256"
  Get-Download $PostgresSha256Url $PostgresHashFile
  $PublishedPostgresHashText = (Get-Content -LiteralPath $PostgresHashFile -Raw).Trim()
  if ($PublishedPostgresHashText -notmatch '(?<hash>[a-fA-F0-9]{64})') { throw 'EDB PostgreSQL SHA-256 sidecar is malformed.' }
  $PublishedPostgresHash = $Matches.hash.ToLowerInvariant()
  if ($PublishedPostgresHash -ne $PostgresSha256Expected) {
    throw "EDB published PostgreSQL checksum sidecar changed: expected $PostgresSha256Expected, got $PublishedPostgresHash"
  }
  Get-Download $PostgresUrl $PostgresZip
  $PostgresActual = Get-Sha256 $PostgresZip
  Write-Host "EDB PostgreSQL 17.11-5 ZIP SHA-256 verified: $PostgresActual"
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
  # Only ship the runtime tree. EDB's archive also contains development headers,
  # documentation and other material that is not needed to run a local cluster.
  foreach ($required in @('bin', 'lib', 'share')) {
    Copy-Item -Path (Join-Path $PostgresRoot $required) -Destination (Join-Path $Assets 'postgres') -Recurse -Force
  }
  # Preserve all upstream PostgreSQL/EDB license and notice files wherever
  # the vendor archive stores them, retaining their relative directory paths.
  $PostgresLicenseFiles = @(Get-ChildItem -LiteralPath $PostgresExtract -File -Recurse |
    Where-Object { $_.Name -match '(?i)(license|copying|copyright|notice)' })
  if ($PostgresLicenseFiles.Count -eq 0) {
    throw 'EDB PostgreSQL archive contains no recognizable license/notice files.'
  }
  $PostgresLicenseRelativePaths = @()
  foreach ($licenseFile in $PostgresLicenseFiles) {
    $licenseRelativePath = [IO.Path]::GetRelativePath($PostgresExtract, $licenseFile.FullName)
    $licenseDestination = Join-Path (Join-Path $Assets 'postgres/licenses') $licenseRelativePath
    $licenseDestinationDirectory = Split-Path -Parent $licenseDestination
    New-Item -ItemType Directory -Force -Path $licenseDestinationDirectory | Out-Null
    Copy-Item -LiteralPath $licenseFile.FullName -Destination $licenseDestination -Force
    $PostgresLicenseRelativePaths += ('postgres/licenses/' + ($licenseRelativePath -replace '\\', '/'))
  }
  Write-Host ('Preserved {0} PostgreSQL license/notice files.' -f $PostgresLicenseFiles.Count)
  Get-ChildItem -LiteralPath (Join-Path $Assets 'postgres') -Filter '*.pdb' -Recurse -File |
    Remove-Item -Force
  # PostgreSQL's packaged manuals are not used by initdb/server/pg_ctl.
  foreach ($documentation in @(
    (Join-Path $Assets 'postgres/share/doc'),
    (Join-Path $Assets 'postgres/share/man')
  )) {
    if (Test-Path -LiteralPath $documentation) {
      Remove-Item -LiteralPath $documentation -Recurse -Force
    }
  }
  # Keep only the PostgreSQL command-line tools required by the desktop lifecycle.
  # DLLs and extension modules are retained; removing them can break server startup
  # or installed SQL extensions. Development-only PGXS files are not needed at runtime.
  $RequiredPostgresExecutables = @('postgres.exe', 'initdb.exe', 'pg_ctl.exe', 'createdb.exe')
  $RemovedPostgresExecutables = @(Get-ChildItem -LiteralPath (Join-Path $Assets 'postgres/bin') -Filter '*.exe' -File |
    Where-Object { $_.Name -notin $RequiredPostgresExecutables })
  foreach ($unusedExecutable in $RemovedPostgresExecutables) {
    Remove-Item -LiteralPath $unusedExecutable.FullName -Force
  }
  $PgxsDirectory = Join-Path $Assets 'postgres/lib/pgxs'
  if (Test-Path -LiteralPath $PgxsDirectory) {
    Remove-Item -LiteralPath $PgxsDirectory -Recurse -Force
  }
  # Translation catalogs are optional; PostgreSQL falls back to English messages
  # when a locale catalog is absent. Keep timezone data and SQL support files intact.
  $PostgresLocaleDirectory = Join-Path $Assets 'postgres/share/locale'
  if (Test-Path -LiteralPath $PostgresLocaleDirectory) {
    Remove-Item -LiteralPath $PostgresLocaleDirectory -Recurse -Force
  }
  foreach ($requiredExecutable in $RequiredPostgresExecutables) {
    if (!(Test-Path -LiteralPath (Join-Path $Assets "postgres/bin/$requiredExecutable"))) {
      throw "PostgreSQL runtime pruning removed a required executable: $requiredExecutable"
    }
  }
  Write-Host ("Removed {0} unused PostgreSQL command-line executables and PGXS development files." -f $RemovedPostgresExecutables.Count)

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

  # Kubo archive and SHA-512 sidecar are fetched from the official GitHub Release; both asset SHA-256 values are pinned to GitHub release metadata.
  $KuboZip = Join-Path $Temp $KuboZipName
  $KuboSidecar = Join-Path $Temp "$KuboZipName.sha512"
  Get-Download "$KuboBase/$KuboZipName" $KuboZip
  Get-Download "$KuboBase/$KuboZipName.sha512" $KuboSidecar
  $KuboSidecarSha256 = Get-Sha256 $KuboSidecar
  if ($KuboSidecarSha256 -ne $KuboSidecarSha256Expected) {
    throw "Kubo SHA-512 sidecar file digest mismatch: expected $KuboSidecarSha256Expected, got $KuboSidecarSha256"
  }
  $KuboZipSha256 = Get-Sha256 $KuboZip
  if ($KuboZipSha256 -ne $KuboZipSha256Expected) {
    throw "Kubo ZIP SHA-256 mismatch against pinned GitHub release asset digest: expected $KuboZipSha256Expected, got $KuboZipSha256"
  }
  $KuboSidecarText = (Get-Content -LiteralPath $KuboSidecar -Raw).Trim()
  if ($KuboSidecarText -notmatch '(?<hash>[a-fA-F0-9]{128})') { throw 'Official Kubo SHA-512 sidecar is malformed.' }
  $KuboExpectedSha512 = $Matches.hash.ToLowerInvariant()
  $KuboActualSha512 = (Get-FileHash -LiteralPath $KuboZip -Algorithm SHA512).Hash.ToLowerInvariant()
  Write-Host "Kubo 0.43.1 ZIP SHA-512 computed: $KuboActualSha512"
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
      postgres = [ordered]@{ version = $PostgresVersion; source = $PostgresUrl; archiveFile = $PostgresArchiveName; file = 'postgres/bin/postgres.exe'; sha256 = $PostgresExeHash }
      kubo = [ordered]@{ version = $KuboVersion; source = "$KuboBase/$KuboZipName"; archiveFile = $KuboZipName; file = 'ipfs/ipfs.exe'; sha256 = $KuboExeHash }
    }
    archiveSha256 = [ordered]@{
      nodeWindowsZip = $NodeActual
      postgresBinariesZip = $PostgresActual
      kuboWindowsZip = $KuboZipSha256
    }
    integrityVerification = [ordered]@{
      nodeShasumsSignature = 'VERIFIED'
      postgresArchiveSha256 = 'VERIFIED'
      postgresAuthenticode = $PostgresSignatureState
      kuboArchiveSha256 = 'VERIFIED'
    }
    licenseFiles = @('runtime/LICENSE', 'ipfs/LICENSE', 'ipfs/LICENSE-APACHE', 'ipfs/LICENSE-MIT') + $PostgresLicenseRelativePaths
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
