[CmdletBinding()]
param(
    [switch]$ApplyBaseline,
    [switch]$SkipRSAT,
    [switch]$ToolsOnly,
    [switch]$SkipBloatwareRemoval,
    [switch]$SkipIPv6Disable,
    [switch]$ForceRedownload
)

# Windows 11 Setup Script - Non-Domain Joined
# ------------------------------------------------------------
# Parameters:
#   -ApplyBaseline        Apply Windows 11 v25H2 Security Baseline (off by default, breaks RDP)
#   -SkipRSAT             Skip RSAT tools installation
#   -SkipBloatwareRemoval Skip bloatware removal
#   -SkipIPv6Disable      Skip IPv6 disabling
#   -ToolsOnly            Only install tools (skip bloatware, IPv6, RSAT)
#   -ForceRedownload      Force re-download of baseline ZIP
#
# Order:
#   1. Pre-flight checks (admin, internet, winget, disk space)
#   2. Remove unwanted apps
#   3. Set region
#   4. Disable IPv6
#   5. Install tooling via winget
#   6. Download pentest tools to C:\tools
#   7. Install RSAT features
#   8. Apply Security Baseline (if -ApplyBaseline)
#   9. Configure firewall for RDP
#  10. Output build summary
#
# NOTE: LGPO.exe is fetched from the provided GitHub link and hash-verified.
# Nessus plugin updates require authenticated Tenable portal access and are not included.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$transcriptPath = Join-Path $env:USERPROFILE "Desktop\ProvisionLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -Append

# =========================================
# Configuration
# =========================================

$script:BaselineZipUrl = "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
$script:LgpoUrl = "https://github.com/paulkwalton/thescriptvault/raw/refs/heads/main/build/LGPO.exe"
$script:LgpoExpectedHash = "C17690302A72FA2B48D31F7BC57B75A73C391F633BE1E9F2BB927681BC2972D7"

# Winget packages with pinned versions. Update versions periodically.
# Note: On PowerShell 5.1 $ErrorActionPreference does not affect native command exit codes.
$script:WingetPackages = @(
    @{ Id = "Microsoft.WindowsTerminal";          Version = "1.23.20211.0" }
    @{ Id = "Iterate.Cyberduck";                   Version = "9.3.1.44136" }
    @{ Id = "Tenable.Nessus";                      Version = "10.11.1.20021" }
    @{ Id = "PortSwigger.BurpSuite.Professional";  Version = "2025.12.4" }
    @{ Id = "Insecure.Nmap";                       Version = "7.80" }
    @{ Id = "WiresharkFoundation.Wireshark";       Version = "4.6.3" }
    @{ Id = "Docker.DockerDesktop";                Version = "4.59.0" }
    @{ Id = "Git.Git";                             Version = "2.53.0" }
    @{ Id = "Microsoft.Sysinternals.Suite";        Version = "" }  # Unpinned: single version in manifest, hash changes frequently
    @{ Id = "Microsoft.Azure.DataStudio";          Version = "1.52.0" }
    @{ Id = "Microsoft.Azure.StorageExplorer";     Version = "1.41.0" }
    @{ Id = "Microsoft.AzureCLI";                  Version = "2.83.0" }
    @{ Id = "Google.Chrome";                       Version = "" }  # Unpinned: Chrome auto-updates, old versions are delisted
    @{ Id = "Kubernetes.kubectl";                  Version = "1.35.0" }
    @{ Id = "Python.Python.3.14";                  Version = "3.14.2" }
    @{ Id = "Bruno.Bruno";                         Version = "3.0.2" }
    @{ Id = "Microsoft.SQLServerManagementStudio"; Version = "20.2.1" }
    @{ Id = "Microsoft.Azure.AZCopy.10";           Version = "10.32.0" }
    @{ Id = "Microsoft.OpenJDK.21";                Version = "21.0.10.7" }
    @{ Id = "Microsoft.Sysinternals.BGInfo";       Version = "4.33" }
    @{ Id = "PuTTY.PuTTY";                        Version = "0.83.0.0" }
    @{ Id = "ElementLabs.LMStudio";               Version = "0.3.39" }
    @{ Id = "OpenAI.Codex";                        Version = "0.95.0" }
)

# Pentest tool downloads with explicit filenames.
# Nessus plugin updates removed: requires authenticated Tenable portal access (URL returned 404).
$script:PentestDownloads = @(
    @{ Url = "https://live.sysinternals.com/ADExplorer.exe";                                                  FileName = "ADExplorer.exe" }
    @{ Url = "https://download.sysinternals.com/files/PSTools.zip";                                            FileName = "PSTools.zip" }
    @{ Url = "https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar"; FileName = "jython-standalone-2.7.4.jar" }
    @{ Url = "https://repo1.maven.org/maven2/org/jruby/jruby-complete/10.0.2.0/jruby-complete-10.0.2.0.jar";  FileName = "jruby-complete-10.0.2.0.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/444407b96d9c4de0adb7aed89e826122/5";            FileName = "403-bypasser.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/f9bbac8c4acf4aefa4d7dc92a991af2f/27";           FileName = "autorize.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/f923cbf91698420890354c1d8958fee6/33";           FileName = "json-web-tokens.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/c61cfa893bb14db4b01775554f7b802e/23";           FileName = "saml-raider.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/0ab7a94d8e11449daaf0fb387431225b/8";             FileName = "js-miner.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/ae62baff8fa24150991bad5eaf6d4d38/15";           FileName = "software-version-reporter.jar" }
    @{ Url = "https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81";                             FileName = "logger-plus-plus.jar" }
    @{ Url = "https://portswigger.net/bappstore/bapps/download/36238b534a78494db9bf2d03f112265c/13";           FileName = "retire-js.jar" }
)

$script:BuildResults = [System.Collections.ArrayList]::new()

# =========================================
# Helper Functions
# =========================================

function Add-BuildResult {
    param(
        [string]$Category,
        [string]$Item,
        [ValidateSet('Success','Failed','Skipped')]
        [string]$Status,
        [string]$Detail = ''
    )
    [void]$script:BuildResults.Add([PSCustomObject]@{
        Category = $Category
        Item     = $Item
        Status   = $Status
        Detail   = $Detail
    })
}

# =========================================
# Functions
# =========================================

function Remove-UnwantedApps {
    Write-Host "`n[+] Removing unwanted Windows apps..." -ForegroundColor Cyan
    $bloatwareApps = @(
        "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.WindowsMaps",
        "Microsoft.MicrosoftSolitaireCollection","Microsoft.BingWeather","Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera","Microsoft.GetHelp","Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub","Microsoft.Microsoft3DViewer","Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay","Microsoft.MixedReality.Portal","Microsoft.People",
        "Microsoft.SkypeApp","Microsoft.MicrosoftStickyNotes","Microsoft.YourPhone",
        "Microsoft.OneConnect","Microsoft.Todos"
    )
    foreach ($app in $bloatwareApps) {
        try {
            Write-Host "[*] Attempting to remove $app..." -ForegroundColor DarkCyan
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "[OK] Removed ${app}" -ForegroundColor Green
            Add-BuildResult -Category 'Bloatware' -Item $app -Status 'Success'
        }
        catch {
            Write-Host "[X] Failed to remove ${app}: $($_.Exception.Message)" -ForegroundColor Red
            Add-BuildResult -Category 'Bloatware' -Item $app -Status 'Failed' -Detail $_.Exception.Message
        }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "[+] Bloatware removal complete." -ForegroundColor Yellow
}

function Disable-IPv6 {
    Write-Host "`n[+] Disabling IPv6 on all network adapters..." -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $name = "DisabledComponents"
        $value = 0xFF
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $name -Value $value -Type DWord
        Write-Host "[OK] Set DisabledComponents registry value to 0xFF." -ForegroundColor Green

        Get-NetAdapter | ForEach-Object {
            try {
                Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            } catch {
                Write-Host "[!] Could not disable IPv6 on adapter $($_.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-Host "[+] IPv6 disabling complete. A reboot may be required for changes to take full effect." -ForegroundColor Yellow
        Add-BuildResult -Category 'Network' -Item 'IPv6 Disable' -Status 'Success'
    }
    catch {
        Write-Host "[X] Failed to disable IPv6: $($_.Exception.Message)" -ForegroundColor Red
        Add-BuildResult -Category 'Network' -Item 'IPv6 Disable' -Status 'Failed' -Detail $_.Exception.Message
    }
}

function Allow-RDP-InboundFirewall {
    Write-Host "`n[+] Disabling Windows Firewall for all profiles..." -ForegroundColor Cyan
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False -ErrorAction Stop
        Write-Host "[OK] Windows Firewall disabled for all profiles." -ForegroundColor Green
        Add-BuildResult -Category 'Firewall' -Item 'Firewall Disable' -Status 'Success'
    }
    catch {
        Write-Host "[X] Failed to disable Windows Firewall: $($_.Exception.Message)" -ForegroundColor Red
        Add-BuildResult -Category 'Firewall' -Item 'Firewall Disable' -Status 'Failed' -Detail $_.Exception.Message
    }
}

function Install-WindowsSecurityBaselineNonDomainJoined {
    param(
        [string]$DownloadRoot = [IO.Path]::Combine($env:USERPROFILE, 'Downloads'),
        [switch]$ForceRedownload
    )
    Write-Host "`n[+] Applying Windows 11 v25H2 Security Baseline (Non-Domain Joined)..." -ForegroundColor Cyan

    $baselineZip = Join-Path $DownloadRoot "Windows11_v25H2_Baseline.zip"
    $extractPath = Join-Path $DownloadRoot "Windows11_v25H2_Baseline_Extracted"

    try {
        if ($ForceRedownload -or -not (Test-Path $baselineZip)) {
            Write-Host "[*] Downloading baseline ZIP..." -ForegroundColor DarkCyan
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $script:BaselineZipUrl -OutFile $baselineZip -UseBasicParsing
        } else {
            Write-Host "[*] Baseline ZIP already present. (Use -ForceRedownload to fetch again.)" -ForegroundColor DarkCyan
        }

        Write-Host "[*] Extracting baseline to: $extractPath" -ForegroundColor DarkCyan
        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        Expand-Archive -Path $baselineZip -DestinationPath $extractPath

        Write-Host "[*] Locating Baseline-LocalInstall.ps1..." -ForegroundColor DarkCyan
        $baselineScript = Get-ChildItem -Path $extractPath -Filter "Baseline-LocalInstall.ps1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $baselineScript) { throw "Baseline-LocalInstall.ps1 not found." }

        $scriptsDir = $baselineScript.DirectoryName
        Write-Host "[OK] Found baseline script at: $scriptsDir" -ForegroundColor Green

        $toolsDir = Join-Path $scriptsDir "Tools"
        if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir | Out-Null }
        $lgpoExePath = Join-Path $toolsDir "LGPO.exe"

        if (-not (Test-Path $lgpoExePath)) {
            Write-Host "[*] LGPO.exe not present. Downloading from provided URL..." -ForegroundColor DarkCyan
            try {
                Invoke-WebRequest -Uri $script:LgpoUrl -OutFile $lgpoExePath -UseBasicParsing -ErrorAction Stop
                if ((Test-Path $lgpoExePath) -and ((Get-Item $lgpoExePath).Length -gt 40KB)) {
                    # Verify SHA256 hash
                    $actualHash = (Get-FileHash -Path $lgpoExePath -Algorithm SHA256).Hash
                    if ($actualHash -ne $script:LgpoExpectedHash) {
                        Write-Host "[X] LGPO.exe hash mismatch!" -ForegroundColor Red
                        Write-Host "    Expected: $($script:LgpoExpectedHash)" -ForegroundColor Red
                        Write-Host "    Actual:   $actualHash" -ForegroundColor Red
                        Remove-Item $lgpoExePath -Force
                        Add-BuildResult -Category 'Baseline' -Item 'LGPO.exe' -Status 'Failed' -Detail 'Hash mismatch'
                        return
                    }
                    Write-Host "[OK] LGPO.exe acquired and hash verified." -ForegroundColor Green
                    Add-BuildResult -Category 'Baseline' -Item 'LGPO.exe' -Status 'Success'
                } else {
                    Write-Host "[X] LGPO.exe download failed or file too small." -ForegroundColor Red
                    Write-Host "    Manual fix: Download Security Compliance Toolkit and place LGPO.exe in:" -ForegroundColor Red
                    Write-Host "    $toolsDir" -ForegroundColor Red
                    Add-BuildResult -Category 'Baseline' -Item 'LGPO.exe' -Status 'Failed' -Detail 'Download too small'
                    return
                }
            }
            catch {
                Write-Host "[X] LGPO.exe download failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "    Manual fix: Download Security Compliance Toolkit and place LGPO.exe in:" -ForegroundColor Red
                Write-Host "    $toolsDir" -ForegroundColor Red
                Add-BuildResult -Category 'Baseline' -Item 'LGPO.exe' -Status 'Failed' -Detail $_.Exception.Message
                return
            }
        } else {
            Write-Host "[OK] LGPO.exe already present." -ForegroundColor Green
        }

        Get-ChildItem -Path $scriptsDir -Recurse | Unblock-File -ErrorAction SilentlyContinue

        Write-Host "[*] Executing baseline script with -Win11NonDomainJoined ..." -ForegroundColor DarkCyan
        Push-Location $scriptsDir
        try {
            & $baselineScript.FullName -Win11NonDomainJoined -ErrorAction Stop
            Write-Host "[OK] Baseline applied successfully." -ForegroundColor Green
            Add-BuildResult -Category 'Baseline' -Item 'Security Baseline' -Status 'Success'
        }
        catch {
            Write-Host "[X] Baseline script failed: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.InvocationInfo) {
                Write-Host "    At: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
            }
            Write-Host "    Confirm LGPO.exe is at: $lgpoExePath" -ForegroundColor Yellow
            Add-BuildResult -Category 'Baseline' -Item 'Security Baseline' -Status 'Failed' -Detail $_.Exception.Message
            return
        }
        finally {
            Pop-Location -ErrorAction SilentlyContinue
        }

        Write-Host "[+] Baseline application finished. Reboot is recommended." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[X] Unexpected failure: $($_.Exception.Message)" -ForegroundColor Red
        Add-BuildResult -Category 'Baseline' -Item 'Security Baseline' -Status 'Failed' -Detail $_.Exception.Message
    }
}

function Download-PentestTool {
    $toolsFolder = "C:\tools"
    if (-not (Test-Path $toolsFolder)) {
        Write-Host "[*] Creating $toolsFolder directory..." -ForegroundColor DarkCyan
        New-Item -ItemType Directory -Path $toolsFolder | Out-Null
    }

    $maxRetries = 3
    $jobs = @()

    foreach ($download in $script:PentestDownloads) {
        $url      = $download.Url
        $fileName = $download.FileName
        $destPath = Join-Path $toolsFolder $fileName

        $jobs += Start-Job -ScriptBlock {
            param($url, $destPath, $fileName, $maxRetries)
            $attempt = 0
            $success = $false
            while ($attempt -lt $maxRetries -and -not $success) {
                $attempt++
                try {
                    & curl.exe -L --fail --silent --show-error -o $destPath $url 2>&1 | Out-Null
                    if ((Test-Path $destPath) -and ((Get-Item $destPath).Length -gt 0)) {
                        $success = $true
                    }
                } catch {
                    # Will retry on next iteration
                }
                if (-not $success -and $attempt -lt $maxRetries) {
                    Start-Sleep -Seconds (2 * $attempt)
                }
            }
            if ($success) {
                Write-Output "OK|$fileName|attempt $attempt/$maxRetries"
            } else {
                Write-Output "FAIL|$fileName|after $maxRetries attempts"
            }
        } -ArgumentList $url, $destPath, $fileName, $maxRetries
    }

    Write-Host "[*] Waiting for all downloads to complete..." -ForegroundColor Cyan
    $jobs | Wait-Job | Out-Null
    foreach ($job in $jobs) {
        $output = Receive-Job -Job $job
        foreach ($line in $output) {
            $parts = $line -split '\|', 3
            if ($parts[0] -eq 'OK') {
                Write-Host "[OK] Downloaded $($parts[1]) ($($parts[2]))." -ForegroundColor Green
                Add-BuildResult -Category 'Download' -Item $parts[1] -Status 'Success'
            } else {
                Write-Host "[X] Failed to download $($parts[1]) ($($parts[2]))." -ForegroundColor Red
                Add-BuildResult -Category 'Download' -Item $parts[1] -Status 'Failed' -Detail $parts[2]
            }
        }
        Remove-Job -Job $job
    }
    Write-Host "[+] Downloads complete." -ForegroundColor Yellow
}

function Enable-AllRSATTools {
    Write-Host "`n[+] Enabling all RSAT (Remote Server Administration Tools) features..." -ForegroundColor Cyan
    try {
        $rsatCapabilities = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'Rsat.*' }
        foreach ($cap in $rsatCapabilities) {
            if ($cap.State -ne 'Installed') {
                Write-Host "[*] Installing $($cap.Name)..." -ForegroundColor DarkCyan
                try {
                    Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
                    Write-Host "[OK] Installed $($cap.Name)." -ForegroundColor Green
                    Add-BuildResult -Category 'RSAT' -Item $cap.Name -Status 'Success'
                } catch {
                    if ($_.Exception.HResult -eq -2146498736) {
                        Write-Host "[X] Failed to install $($cap.Name): Feature on Demand (FoD) source unavailable (0x800f0950)." -ForegroundColor Red
                        Write-Host "    Ensure Windows Update is accessible, or configure a local FoD source:" -ForegroundColor Yellow
                        Write-Host "    Group Policy > Computer Configuration > Administrative Templates > System >" -ForegroundColor Yellow
                        Write-Host "    'Specify settings for optional component installation and component repair'" -ForegroundColor Yellow
                        Add-BuildResult -Category 'RSAT' -Item $cap.Name -Status 'Failed' -Detail 'FoD source unavailable (0x800f0950)'
                    } else {
                        Write-Host "[X] Failed to install $($cap.Name): $($_.Exception.Message)" -ForegroundColor Red
                        Add-BuildResult -Category 'RSAT' -Item $cap.Name -Status 'Failed' -Detail $_.Exception.Message
                    }
                }
            } else {
                Write-Host "[OK] $($cap.Name) already installed." -ForegroundColor Green
                Add-BuildResult -Category 'RSAT' -Item $cap.Name -Status 'Success' -Detail 'Already installed'
            }
        }
        Write-Host "[+] RSAT tool installation complete." -ForegroundColor Yellow
    }
    catch {
        Write-Host "[X] Failed to enumerate RSAT tools: $($_.Exception.Message)" -ForegroundColor Red
        Add-BuildResult -Category 'RSAT' -Item 'RSAT Enumeration' -Status 'Failed' -Detail $_.Exception.Message
    }
}

function Install-WingetPackages {
    Write-Host "`n[+] Installing packages via winget..." -ForegroundColor Cyan

    $sourceUpdateProcess = Start-Process -FilePath 'winget' -ArgumentList @('source', 'update') -Wait -PassThru -NoNewWindow
    if ($sourceUpdateProcess.ExitCode -ne 0) {
        Write-Host "[!] winget source update returned exit code $($sourceUpdateProcess.ExitCode)." -ForegroundColor Yellow
    }

    foreach ($pkg in $script:WingetPackages) {
        $id = $pkg.Id
        $version = $pkg.Version

        $wingetArgs = @('install', '-e', '--id', $id, '--accept-package-agreements', '--accept-source-agreements', '--silent')
        if ($version) {
            $wingetArgs += @('--version', $version)
            Write-Host "[*] Installing $id (v$version)..." -ForegroundColor DarkCyan
        } else {
            Write-Host "[*] Installing $id (latest)..." -ForegroundColor DarkCyan
        }

        try {
            $process = Start-Process -FilePath 'winget' -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -eq 0) {
                Write-Host "[OK] Installed $id." -ForegroundColor Green
                Add-BuildResult -Category 'Winget' -Item $id -Status 'Success'
            } elseif ($process.ExitCode -eq -1978335189) {
                Write-Host "[OK] $id already installed." -ForegroundColor Green
                Add-BuildResult -Category 'Winget' -Item $id -Status 'Success' -Detail 'Already installed'
            } else {
                Write-Host "[X] Failed to install $id (exit code: $($process.ExitCode))." -ForegroundColor Red
                Add-BuildResult -Category 'Winget' -Item $id -Status 'Failed' -Detail "Exit code: $($process.ExitCode)"
            }
        } catch {
            Write-Host "[X] Exception installing ${id}: $($_.Exception.Message)" -ForegroundColor Red
            Add-BuildResult -Category 'Winget' -Item $id -Status 'Failed' -Detail $_.Exception.Message
        }
    }
    Write-Host "[+] Winget installation complete." -ForegroundColor Yellow
}

function Test-Prerequisites {
    Write-Host "`n[+] Running pre-flight checks..." -ForegroundColor Cyan
    $failures = @()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator
    )
    if (-not $isAdmin) {
        $failures += "Script must be run as Administrator."
    } else {
        Write-Host "[OK] Running as Administrator." -ForegroundColor Green
    }

    try {
        $connectivity = Test-NetConnection -ComputerName "www.microsoft.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($connectivity) {
            Write-Host "[OK] Internet connectivity verified." -ForegroundColor Green
        } else {
            $failures += "Cannot reach www.microsoft.com:443. Internet required."
        }
    } catch {
        $failures += "Internet connectivity check failed: $($_.Exception.Message)"
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "[OK] winget is available." -ForegroundColor Green
    } else {
        $failures += "winget is not installed or not in PATH."
    }

    $freeGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
    if ($freeGB -ge 20) {
        Write-Host "[OK] Disk space: ${freeGB}GB free on C:\" -ForegroundColor Green
    } else {
        $failures += "Low disk space: ${freeGB}GB free (20GB minimum recommended)."
    }

    if ($failures.Count -gt 0) {
        Write-Host "`n[X] Pre-flight checks FAILED:" -ForegroundColor Red
        foreach ($f in $failures) {
            Write-Host "    - $f" -ForegroundColor Red
        }
        throw "Pre-flight checks failed. Resolve the above issues before running."
    }
    Write-Host "[+] All pre-flight checks passed." -ForegroundColor Yellow
}

function Write-BuildSummary {
    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "           BUILD SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "Hostname  : $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "Log file  : $transcriptPath" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Cyan

    $grouped = $script:BuildResults | Group-Object -Property Category
    foreach ($group in $grouped) {
        Write-Host "`n--- $($group.Name) ---" -ForegroundColor Yellow
        foreach ($r in $group.Group) {
            $color = switch ($r.Status) {
                'Success' { 'Green' }
                'Failed'  { 'Red' }
                'Skipped' { 'DarkGray' }
            }
            $line = "  [$($r.Status)] $($r.Item)"
            if ($r.Detail) { $line += " - $($r.Detail)" }
            Write-Host $line -ForegroundColor $color
        }
    }

    $total   = $script:BuildResults.Count
    $success = @($script:BuildResults | Where-Object Status -eq 'Success').Count
    $failed  = @($script:BuildResults | Where-Object Status -eq 'Failed').Count
    $skipped = @($script:BuildResults | Where-Object Status -eq 'Skipped').Count
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $success succeeded, $failed failed, $skipped skipped (of $total total)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# =========================================
# Main Execution
# =========================================

try {
    if ($ToolsOnly) {
        $SkipBloatwareRemoval = $true
        $SkipIPv6Disable = $true
        $SkipRSAT = $true
    }

    Test-Prerequisites

    # Bloatware removal
    if (-not $SkipBloatwareRemoval) {
        Remove-UnwantedApps
    } else {
        Write-Host "[*] Skipping bloatware removal (-SkipBloatwareRemoval)." -ForegroundColor DarkGray
        Add-BuildResult -Category 'Bloatware' -Item 'Bloatware Removal' -Status 'Skipped'
    }

    # Region
    Set-WinHomeLocation -GeoId 244

    # IPv6
    if (-not $SkipIPv6Disable) {
        Disable-IPv6
    } else {
        Write-Host "[*] Skipping IPv6 disable (-SkipIPv6Disable)." -ForegroundColor DarkGray
        Add-BuildResult -Category 'Network' -Item 'IPv6 Disable' -Status 'Skipped'
    }

    # Winget packages
    Install-WingetPackages

    # Defender exclusion for C:\tools before downloads
    Write-Host "`n[+] Adding Windows Defender exclusion for C:\tools\ ..." -ForegroundColor Cyan
    try {
        Add-MpPreference -ExclusionPath "C:\tools"
        Write-Host "[OK] Windows Defender exclusion added for C:\tools\" -ForegroundColor Green
        Add-BuildResult -Category 'Security' -Item 'Defender Exclusion (C:\tools)' -Status 'Success'
    } catch {
        Write-Host "[X] Failed to add Windows Defender exclusion: $($_.Exception.Message)" -ForegroundColor Red
        Add-BuildResult -Category 'Security' -Item 'Defender Exclusion (C:\tools)' -Status 'Failed' -Detail $_.Exception.Message
    }

    # Pentest tool downloads
    Download-PentestTool

    # RSAT tools
    if (-not $SkipRSAT) {
        Enable-AllRSATTools
    } else {
        Write-Host "[*] Skipping RSAT installation (-SkipRSAT)." -ForegroundColor DarkGray
        Add-BuildResult -Category 'RSAT' -Item 'RSAT Tools' -Status 'Skipped'
    }

    # Security baseline (opt-in only)
    if ($ApplyBaseline) {
        Install-WindowsSecurityBaselineNonDomainJoined -ForceRedownload:$ForceRedownload
    } else {
        Write-Host "[*] Skipping security baseline (use -ApplyBaseline to enable)." -ForegroundColor DarkGray
        Add-BuildResult -Category 'Baseline' -Item 'Security Baseline' -Status 'Skipped'
    }

    # Firewall
    Allow-RDP-InboundFirewall

} catch {
    Write-Host "`n[X] Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "    At: $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
    }
} finally {
    Write-BuildSummary
    Write-Host "`n[+] Script finished. Reboot recommended if baseline was applied." -ForegroundColor Yellow
    Stop-Transcript
}
