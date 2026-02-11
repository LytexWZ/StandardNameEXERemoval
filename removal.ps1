$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    Malware Cleanup Script - By LytexWZ" -ForegroundColor Cyan
Write-Host "    Target: StandardName / zgRAT Loader" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Not running as Administrator. Requesting elevation..." -ForegroundColor Yellow
    
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -ArgumentList "-NoProfile","-ExecutionPolicy Bypass","-File `"$scriptPath`"" -Verb RunAs
        exit
    } catch {
        Write-Host "[X] ERROR: Failed to elevate privileges!" -ForegroundColor Red
        Write-Host "[!] Please right-click the script and select 'Run as Administrator'" -ForegroundColor Yellow
        pause
        exit 1
    }
}

Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green

$CurrentUser = $env:USERNAME
$AllUserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

Write-Host "[*] Current user: $CurrentUser" -ForegroundColor Cyan
Write-Host "[*] Will scan all user profiles on this system" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Step 1: Stopping suspicious processes..." -ForegroundColor Yellow

$BadProcesses = @(
    "StandardName",
    "RegAsm",
    "MSBuild",
    "InstallUtil",
    "aspnet_compiler",
    "RegSvcs",
    "AddInProcess"
)

$stoppedCount = 0
foreach ($proc in $BadProcesses) {
    $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($processes) {
        foreach ($p in $processes) {
            try {
                Stop-Process -Id $p.Id -Force
                Write-Host "  [OK] Stopped: $($p.Name)  (PID: $($p.Id))" -ForegroundColor Green
                $stoppedCount++
            } catch {
                Write-Host "  [!] Failed to stop: $($p.Name) - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

if ($stoppedCount -eq 0) {
    Write-Host "  [i] No suspicious processes found running" -ForegroundColor Gray
}

Write-Host ""

Write-Host "[*] Step 2: Removing Defender exclusions..." -ForegroundColor Yellow

$ExclusionPaths = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AppLaunch.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess.exe"
)

foreach ($profile in $AllUserProfiles) {
    $ExclusionPaths += "$($profile.FullName)\AppData\Roaming\Name\StandardName.exe"
}

$ExclusionProcesses = @(
    "StandardName.exe",
    "InstallUtil.exe",
    "RegAsm.exe",
    "MSBuild.exe",
    "aspnet_compiler.exe",
    "AppLaunch.exe",
    "RegSvcs.exe",
    "AddInProcess.exe"
)

$removedPathCount = 0
$notFoundPathCount = 0

$currentPrefs = Get-MpPreference

foreach ($path in $ExclusionPaths) {
    if ($currentPrefs.ExclusionPath -contains $path) {
        try {
            Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Host "  [OK] Removed path exclusion: $path" -ForegroundColor Green
            $removedPathCount++
        } catch {
            Write-Host "  [X] ERROR: Failed to remove path exclusion: $path - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [!] Path exclusion not found (clean): $path" -ForegroundColor DarkGray
        $notFoundPathCount++
    }
}

$removedProcCount = 0
$notFoundProcCount = 0
foreach ($proc in $ExclusionProcesses) {
    if ($currentPrefs.ExclusionProcess -contains $proc) {
        try {
            Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  [OK] Removed process exclusion: $proc" -ForegroundColor Green
            $removedProcCount++
        } catch {
            Write-Host "  [X] ERROR: Failed to remove process exclusion: $proc - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [!] Process exclusion not found (clean): $proc" -ForegroundColor DarkGray
        $notFoundProcCount++
    }
}

if ($removedPathCount -eq 0 -and $removedProcCount -eq 0) {
    Write-Host "  [i] No malicious exclusions were removed ($($notFoundPathCount + $notFoundProcCount) checked and clean)" -ForegroundColor Gray
}

Write-Host ""

Write-Host "[*] Step 3: Removing malware files..." -ForegroundColor Yellow

$deletedCount = 0
$notFoundCount = 0

foreach ($profile in $AllUserProfiles) {
    $searchPaths = @(
        "$($profile.FullName)\AppData\Roaming\Name",
        "$($profile.FullName)\AppData\Local\Temp",
        "$($profile.FullName)\AppData\Roaming"
    )
    
    foreach ($folder in $searchPaths) {
        if (Test-Path $folder) {
            try {
                $foundFiles = Get-ChildItem $folder -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*StandardName*" }
                
                if ($foundFiles) {
                    $foundFiles | ForEach-Object {
                        try {
                            Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop
                            Write-Host "  [OK] Deleted: $($_.FullName)" -ForegroundColor Green
                            $deletedCount++
                        } catch {
                            Write-Host "  [X] ERROR: Failed to delete: $($_.FullName) - $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            } catch {
                Write-Host "  [X] ERROR: Failed to scan folder: $folder - $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  [!] Path not found (no infection): $folder" -ForegroundColor DarkGray
            $notFoundCount++
        }
    }
    
    $malwareFolder = "$($profile.FullName)\AppData\Roaming\Name"
    if (Test-Path $malwareFolder) {
        try {
            Remove-Item $malwareFolder -Force -Recurse -ErrorAction Stop
            Write-Host "  [OK] Removed folder: $malwareFolder" -ForegroundColor Green
            $deletedCount++
        } catch {
            Write-Host "  [X] ERROR: Failed to remove: $malwareFolder - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [!] Malware folder not found (clean): $malwareFolder" -ForegroundColor DarkGray
        $notFoundCount++
    }
}

if ($deletedCount -eq 0) {
    Write-Host "  [i] No malware files were deleted ($notFoundCount locations checked and clean)" -ForegroundColor Gray
}

Write-Host ""

Write-Host "[*] Step 4: Removing Scheduled Tasks and Registry Entries..." -ForegroundColor Yellow

$removedRegCount = 0

$machineRunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $machineRunKeys) {
    if (Test-Path $key) {
        try {
            $props = Get-ItemProperty $key -ErrorAction Stop
            $propNames = $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }
            
            foreach ($prop in $propNames) {
                if ($props.$($prop.Name) -like "*StandardName*" -or $props.$($prop.Name) -like "*\Name\*") {
                    Remove-ItemProperty -Path $key -Name $prop.Name -Force -ErrorAction Stop
                    Write-Host "  [OK] Removed startup entry: $($prop.Name)" -ForegroundColor Green
                    $removedRegCount++
                }
            }
        } catch {
        }
    }
}

$removedTaskCount = 0
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop |
    Where-Object {
        $_.TaskPath -like "*StandardName*" -or
        $_.TaskName -like "*StandardName*"
    }
    
    foreach ($task in $tasks) {
        try {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-Host "  [OK] Removed scheduled task: $($task.TaskName)" -ForegroundColor Green
            $removedTaskCount++
        } catch {
            Write-Host "  [!] Failed to remove task: $($task.TaskName)" -ForegroundColor Red
        }
    }
} catch {
}

if ($removedRegCount -eq 0 -and $removedTaskCount -eq 0) {
    Write-Host "  [i] No persistence mechanisms found" -ForegroundColor Gray
}

Write-Host ""

Write-Host "[*] Step 5: Restoring Windows Defender configuration..." -ForegroundColor Yellow

try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Host "  [OK] Real-time monitoring enabled" -ForegroundColor Green
    
    Set-MpPreference -DisableIOAVProtection $false
    Write-Host "  [OK] IOAV protection enabled" -ForegroundColor Green
    
    Set-MpPreference -DisableScriptScanning $false
    Write-Host "  [OK] Script scanning enabled" -ForegroundColor Green
    
    Set-MpPreference -DisableBehaviorMonitoring $false
    Write-Host "  [OK] Behavior monitoring enabled" -ForegroundColor Green
    
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    Write-Host "  [OK] Intrusion prevention enabled" -ForegroundColor Green
    
    Set-MpPreference -MAPSReporting Advanced
    Write-Host "  [OK] Cloud-delivered protection enabled" -ForegroundColor Green
    
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Write-Host "  [OK] Automatic sample submission enabled" -ForegroundColor Green
    
    Set-MpPreference -EnableControlledFolderAccess Enabled
    Write-Host "  [OK] Controlled folder access enabled" -ForegroundColor Green
    
    Set-MpPreference -EnableNetworkProtection Enabled
    Write-Host "  [OK] Network protection enabled" -ForegroundColor Green
    
    Set-MpPreference -PUAProtection Enabled
    Write-Host "  [OK] PUA protection enabled" -ForegroundColor Green
    
} catch {
    Write-Host "  [!] Some Defender settings may have failed to restore: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

Write-Host "[*] Step 6: Updating Windows Defender signatures..." -ForegroundColor Yellow

try {
    Update-MpSignature -ErrorAction Stop
    Write-Host "  [OK] Defender signatures updated" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed to update signatures: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "    CLEANUP COMPLETED" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[!] CRITICAL NEXT STEPS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. REBOOT the system IMMEDIATELY" -ForegroundColor Red
Write-Host "  2. After reboot, change ALL passwords" -ForegroundColor Red
Write-Host "     - Windows password" -ForegroundColor White
Write-Host "     - Email accounts" -ForegroundColor White
Write-Host "     - Banking/Financial accounts" -ForegroundColor White
Write-Host "     - Social media accounts" -ForegroundColor White
Write-Host "  3. Enable 2FA everywhere possible" -ForegroundColor Yellow
Write-Host "  4. Monitor accounts for suspicious activity" -ForegroundColor Yellow
Write-Host "  5. Run a malware scan and review results" -ForegroundColor Yellow
Write-Host ""
Write-Host "[!] For maximum security, consider a clean OS reinstall" -ForegroundColor Magenta
Write-Host ""

$logPath = "$env:USERPROFILE\Desktop\MalwareCleanup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logContent = @"
Malware Cleanup Script Execution Log
Created by lytexWZ
===================================
Date: $(Get-Date)
User: $CurrentUser
Computer: $env:COMPUTERNAME

Actions Taken:
- Stopped processes: $stoppedCount
- Removed Defender exclusions: $($removedPathCount + $removedProcCount)
- Deleted malware files: $deletedCount
- Removed persistence entries: $($removedRegCount + $removedTaskCount)
- Defender configuration restored
- Full system scan initiated

Next Steps:
1. Reboot immediately
2. Change all passwords
3. Enable 2FA everywhere
4. Monitor accounts for suspicious activity
5. Consider clean OS reinstall for maximum security
"@

try {
    $logContent | Out-File -FilePath $logPath -Encoding UTF8
    Write-Host "[OK] Log file created: $logPath" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not create log file" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Cleanup completed. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
