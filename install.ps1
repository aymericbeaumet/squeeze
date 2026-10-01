# Install squeeze (https://github.com/aymericbeaumet/squeeze) on Windows from
# its GitHub releases:
#
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.ps1 | iex"
#
# Options are environment variables:
#
#   SQUEEZE_VERSION      release to install, e.g. 0.3.0 (default: latest)
#   SQUEEZE_INSTALL_DIR  install directory (default: %LOCALAPPDATA%\Programs\squeeze\bin)
#
#   $env:SQUEEZE_VERSION = '0.3.0'; irm https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.ps1 | iex
#
# The archive is checked against the release's SHA256SUMS before it is
# extracted. squeeze is installed for the current user only (no administrator
# rights needed), and the install directory is added to the user PATH.

# Everything runs inside this script block: a truncated download fails to parse
# instead of running half a script, and preferences set here do not leak into
# the caller's session.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # the progress bar slows downloads down a lot in Windows PowerShell
    $repo = 'https://github.com/aymericbeaumet/squeeze'
    $sourceInstall = "cargo install --locked squeeze-cli"

    function Save-Url($uri, $file) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $file
        } catch {
            # Only keep the exception message: the error record embeds GitHub's HTML error page.
            throw "Could not download ${uri}: $($_.Exception.Message)"
        }
    }

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell may default to TLS 1.0, which GitHub rejects.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    # PROCESSOR_ARCHITECTURE describes the current process, which may be
    # emulated: x86 processes see PROCESSOR_ARCHITEW6432, and x64 processes on
    # ARM64 are only caught by OSArchitecture.
    $archs = @($env:PROCESSOR_ARCHITEW6432, $env:PROCESSOR_ARCHITECTURE)
    $runtimeInformation = 'System.Runtime.InteropServices.RuntimeInformation' -as [type] # .NET Framework 4.7.1+
    if ($runtimeInformation) { $archs += $runtimeInformation::OSArchitecture.ToString() }
    if ($archs -contains 'ARM64') {
        $arch = 'arm64'
    } elseif ($archs -contains 'AMD64' -or $archs -contains 'X64') {
        $arch = 'amd64'
    } else {
        throw "No prebuilt squeeze binary for $env:PROCESSOR_ARCHITECTURE Windows. Build it from source with Rust instead:`n  $sourceInstall`nor see $repo/releases"
    }

    $version = $env:SQUEEZE_VERSION
    if (-not $version) {
        # GitHub redirects /releases/latest to /releases/tag/vX.Y.Z. Reading that
        # redirect avoids the rate-limited API.
        $response = (Invoke-WebRequest -UseBasicParsing -Method Head -Uri "$repo/releases/latest").BaseResponse
        if ($response -is [Net.HttpWebResponse]) {
            $final = $response.ResponseUri # Windows PowerShell
        } else {
            $final = $response.RequestMessage.RequestUri # PowerShell 6+
        }
        if ("$final" -notmatch '/releases/tag/([^/?#]+)$') {
            throw "Could not determine the latest release from $repo/releases/latest"
        }
        $version = $Matches[1]
    }
    $version = $version -replace '^v', ''
    if ($version -notmatch '^[0-9A-Za-z.+-]+$') { throw "Invalid version: $version" }
    $tag = "v$version"
    $asset = "squeeze-$tag-windows-$arch.zip"
    $url = "$repo/releases/download/$tag"

    $dir = $env:SQUEEZE_INSTALL_DIR
    if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\squeeze\bin' }
    $dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($dir).TrimEnd('\')
    $exe = Join-Path $dir 'squeeze.exe'

    Write-Host "Installing squeeze $tag (windows-$arch) to $dir"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "squeeze-$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $sums = Join-Path $tmp 'SHA256SUMS'
        $zip = Join-Path $tmp $asset
        try {
            Save-Url "$url/SHA256SUMS" $sums
        } catch {
            throw "$($_.Exception.Message)`nDoes release $tag exist? See $repo/releases"
        }
        Save-Url "$url/$asset" $zip

        $expected = foreach ($line in Get-Content $sums) {
            $hash, $name = $line -split '\s+', 2
            if ($name -eq $asset) { $hash; break }
        }
        if (-not $expected) { throw "$asset is not listed in SHA256SUMS" }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "Checksum mismatch for $asset (expected $expected, got $actual); not installing"
        }
        Write-Host "Verified SHA-256 checksum of $asset"

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, (Join-Path $tmp 'x'))
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Copy-Item -Force -Path (Join-Path $tmp 'x\squeeze.exe') -Destination $exe
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }

    try {
        $installed = & $exe --version 2>&1
        if ($LASTEXITCODE -eq -1073741515) { # STATUS_DLL_NOT_FOUND
            throw "a DLL is missing; installing the Microsoft Visual C++ Redistributable should fix it: https://aka.ms/vs/17/release/vc_redist.$($arch -replace 'amd64', 'x64').exe"
        }
        if ($LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE`n$installed" }
    } catch {
        throw "Installed $exe, but it failed to run: $($_.Exception.Message)`nPlease report this at $repo/issues, or build from source instead:`n  $sourceInstall"
    }
    Write-Host "Installed $installed to $exe"

    # Edit the registry value directly: [Environment]::SetEnvironmentVariable
    # would store the user PATH as REG_SZ, breaking entries that reference
    # other variables such as %USERPROFILE%.
    $inPath = { param($path) $path -split ';' | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -eq $dir } }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $userPath = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        $pathChanged = -not (& $inPath $userPath)
        if ($pathChanged) {
            if ($userPath -and -not $userPath.EndsWith(';')) { $userPath += ';' }
            $key.SetValue('Path', "$userPath$dir", 'ExpandString')
        }
    } finally {
        $key.Close()
    }
    if ($pathChanged) {
        # Setting any user variable broadcasts WM_SETTINGCHANGE, so terminals
        # opened from now on see the new PATH.
        [Environment]::SetEnvironmentVariable('SQUEEZE_PATH_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('SQUEEZE_PATH_REFRESH', [NullString]::Value, 'User')
    }
    if (-not (& $inPath $env:Path)) { $env:Path = "$env:Path;$dir" }

    $found = (Get-Command squeeze -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Path
    if ($found -and $found -ne $exe) {
        Write-Host "Note: 'squeeze' currently resolves to $found, which comes first on your PATH."
    }
    if ($pathChanged) {
        Write-Host "`nAdded $dir to your user PATH. Restart your terminal to use squeeze."
    }
    Write-Host "`nTry it: 'see https://example.com' | squeeze --url"
}
