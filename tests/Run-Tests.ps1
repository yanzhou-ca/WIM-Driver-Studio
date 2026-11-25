[CmdletBinding()]
param(
    [string]$ScriptPath
)

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $testDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
    $ScriptPath = Join-Path (Split-Path -Parent -Path $testDirectory) 'WIM_Driver_Studio.ps1'
}

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [object]$Expected,
        [object]$Actual,
        [string]$Message
    )

    if ($Expected -cne $Actual) {
        throw "$Message Expected=[$Expected] Actual=[$Actual]"
    }
}

function Invoke-Test {
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name`: $($_.Exception.Message)"
        Write-Host $_.ScriptStackTrace
    }
}

try {
    . $ScriptPath -LibraryOnly
}
catch {
    Write-Host "FAIL library-load`: $($_.Exception.Message)"
    exit 1
}

if (-not (Get-Command -Name 'Write-ApplicationLog' -ErrorAction SilentlyContinue)) {
    function Write-ApplicationLog {
        param(
            [string]$Message,
            [object]$Level = 'Info'
        )
    }
}

Invoke-Test 'native arguments escape trailing backslashes' {
    $actual = ConvertTo-NativeArgument -Value 'C:\Temp Mount\'
    Assert-Equal -Expected '"C:\Temp Mount\\"' -Actual $actual -Message 'Trailing backslash quoting is incorrect.'
}

Invoke-Test 'native arguments escape embedded quotes' {
    $actual = ConvertTo-NativeArgument -Value 'C:\Temp\"evil'
    Assert-Equal -Expected '"C:\Temp\\\"evil"' -Actual $actual -Message 'Embedded quote quoting is incorrect.'
}

Invoke-Test 'DISM resolves only to the trusted system executable' {
    $expected = Join-Path $env:SystemRoot 'System32\dism.exe'
    $actual = Get-TrustedDismPath
    Assert-Equal -Expected $expected -Actual $actual -Message 'DISM path is not the trusted system path.'
    Assert-True -Condition ([System.IO.File]::Exists($actual)) -Message 'Trusted DISM executable does not exist.'
}

Invoke-Test 'unknown image types fail closed' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $infPath = Join-Path $tempRoot 'test.inf'
        'Class=MEDIA' | Out-File -FilePath $infPath -Encoding UTF8
        $driver = [DriverInfo]::new($infPath)
        $result = Test-DriverSuitabilityForImage -Driver $driver -ImageType ([WimImageType]::Unknown) -ImageArchitecture 'Unknown'
        Assert-True -Condition (-not $result.Suitable) -Message 'Unknown image type must not be recommended.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'unknown image architecture fails closed' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $infPath = Join-Path $tempRoot 'test.inf'
        'Class=MEDIA' | Out-File -LiteralPath $infPath -Encoding UTF8
        $driver = [DriverInfo]::new($infPath)
        $result = Test-DriverSuitabilityForImage -Driver $driver -ImageType ([WimImageType]::Install) -ImageArchitecture 'Unknown'
        Assert-True -Condition (-not $result.Suitable) -Message 'Unknown image architecture must not be recommended.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'unrelated signed binaries do not sign an INF package' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $infPath = Join-Path $tempRoot 'unsigned.inf'
        'Class=MEDIA' | Out-File -FilePath $infPath -Encoding UTF8
        $signedSource = Join-Path $env:SystemRoot 'System32\kernel32.dll'
        Copy-Item -LiteralPath $signedSource -Destination (Join-Path $tempRoot 'kernel32.dll') -Force
        Copy-Item -LiteralPath $signedSource -Destination (Join-Path $tempRoot 'unsigned.cat') -Force
        Add-Content -LiteralPath $infPath -Value '[SourceDisksNames]' -Encoding UTF8
        Add-Content -LiteralPath $infPath -Value '1 = disk1, kernel32.dll' -Encoding UTF8

        $driver = [DriverInfo]::new($infPath)
        Assert-True -Condition ($driver.SignatureStatus -ne 'Signed') -Message 'An unrelated signed DLL or renamed catalog must not mark the INF as signed.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'mount cleanup refuses arbitrary nonempty directories' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $sentinel = Join-Path $tempRoot 'keep.txt'
        'keep' | Out-File -LiteralPath $sentinel -Encoding UTF8
        $result = Clear-ApplicationMountDirectory -MountPath $tempRoot
        Assert-True -Condition (-not $result) -Message 'Arbitrary nonempty directory cleanup must fail.'
        Assert-True -Condition ([System.IO.File]::Exists($sentinel)) -Message 'Arbitrary directory contents were deleted.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'application mount directories are owned and removable' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $mountPath = New-ApplicationMountDirectory -ParentPath $tempRoot
        Assert-True -Condition ([System.IO.Directory]::Exists($mountPath)) -Message 'Mount directory was not created.'
        Assert-Equal -Expected 0 -Actual @(Get-ChildItem -LiteralPath $mountPath -Force).Count -Message 'DISM mount directory must be empty.'
        Assert-True -Condition (Test-ApplicationMountDirectory -MountPath $mountPath) -Message 'Created mount directory is not recognized as application-owned.'
        Assert-True -Condition (Clear-ApplicationMountDirectory -MountPath $mountPath) -Message 'Owned mount directory cleanup failed.'
        Assert-True -Condition (-not [System.IO.Directory]::Exists($mountPath)) -Message 'Owned mount directory was not removed.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'mount cleanup rejects arbitrary directories before DISM runs' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $sentinel = Join-Path $tempRoot 'keep.txt'
        'keep' | Out-File -LiteralPath $sentinel -Encoding UTF8
        $result = Clear-MountDirectory -MountPath $tempRoot
        Assert-True -Condition (-not $result) -Message 'Clear-MountDirectory must reject an unowned directory.'
        Assert-True -Condition ([System.IO.File]::Exists($sentinel)) -Message 'Clear-MountDirectory deleted unowned data.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'mount preparation leaves an owned empty directory in place' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    try {
        $mountPath = New-ApplicationMountDirectory -ParentPath $tempRoot
        $result = Clear-MountDirectory -MountPath $mountPath
        Assert-True -Condition $result -Message 'Owned mount directory preparation failed.'
        Assert-True -Condition ([System.IO.Directory]::Exists($mountPath)) -Message 'Preparation removed the directory DISM needs.'
        Assert-Equal -Expected 0 -Actual @(Get-ChildItem -LiteralPath $mountPath -Force).Count -Message 'Prepared mount directory is not empty.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'DISM process info uses trusted executable and native quoting' {
    $processInfo = New-DismProcessStartInfo -Operation '/Mount-Image' -Arguments @{
        ImageFile = 'C:\My Images\install.wim'
        MountDir  = 'C:\Mount Dir\'
        Index     = 1
    }
    Assert-Equal -Expected (Get-TrustedDismPath) -Actual $processInfo.FileName -Message 'ProcessStartInfo does not use trusted DISM.'
    Assert-True -Condition ($processInfo.Arguments -like '* /ImageFile:"C:\My Images\install.wim"*') -Message 'ImageFile argument is not quoted correctly.'
    Assert-True -Condition ($processInfo.Arguments -like '* /MountDir:"C:\Mount Dir\\"*') -Message 'MountDir trailing backslash is not escaped correctly.'
    Assert-True -Condition (-not $processInfo.UseShellExecute) -Message 'DISM must not use shell execution.'
}

Invoke-Test 'DISM output is requested in English for stable parsing' {
    $processInfo = New-DismProcessStartInfo -Operation '/Get-WimInfo' -Arguments @{ WimFile = 'C:\Images\install.wim' }
    Assert-True -Condition ($processInfo.Arguments.StartsWith('/English ')) -Message 'DISM output must be requested in English.'
}

Invoke-Test 'sensitive output masks usernames in local paths' {
    $sanitized = Protect-SensitiveOutput -OutputText 'C:\Users\Alice\Documents\install.wim'
    Assert-True -Condition ($sanitized -notmatch '(?i)C:\\Users\\Alice\\') -Message 'Username remained in logged path.'
    Assert-True -Condition ($sanitized -match '(?i)C:\\Users\\%USER%\\') -Message 'Masked username placeholder is missing.'
}

Invoke-Test 'operation message queues preserve order across threads' {
    $queue = New-OperationMessageQueue
    Send-OperationMessage -Queue $queue -Message 'first' -Level 'Info'
    Send-OperationMessage -Queue $queue -Message 'second' -Level 'Warning'
    $first = Take-OperationMessage -Queue $queue
    $second = Take-OperationMessage -Queue $queue
    Assert-Equal -Expected 'first' -Actual $first.Message -Message 'First queue message was lost or reordered.'
    Assert-Equal -Expected 'Warning' -Actual $second.Level -Message 'Second queue message metadata was lost.'
    Assert-True -Condition ($null -eq (Take-OperationMessage -Queue $queue)) -Message 'Empty queue must return null.'
}

Invoke-Test 'background logging and progress use the operation queue' {
    $queue = New-OperationMessageQueue
    $script:OperationMessageQueue = $queue
    try {
        Write-ApplicationLog 'background log' ([LogLevel]::Warning)
        Update-ApplicationProgress 42 'background progress'
        $log = Take-OperationMessage -Queue $queue
        $progress = Take-OperationMessage -Queue $queue
        Assert-Equal -Expected 'background log' -Actual $log.Message -Message 'Background log was not queued.'
        Assert-Equal -Expected 42 -Actual $progress.Progress -Message 'Background progress was not queued.'
    }
    finally {
        $script:OperationMessageQueue = $null
    }
}

Invoke-Test 'application state tracks mount path and inventory index' {
    $state = [ThreadSafeApplicationState]::new()
    $state.SetCurrentMountPath('C:\\Temp\\WIMDS-Test')
    $state.SetCurrentInventoryIndex(3)
    $state.SetCurrentWimIndexes(@(1, 3))
    Assert-Equal -Expected 'C:\\Temp\\WIMDS-Test' -Actual $state.GetCurrentMountPath() -Message 'Mount path was not retained.'
    Assert-Equal -Expected 3 -Actual $state.GetCurrentInventoryIndex() -Message 'Inventory index was not retained.'
    Assert-Equal -Expected 2 -Actual $state.GetCurrentWimIndexes().Count -Message 'WIM indexes were not retained.'
    $state.Reset()
    Assert-True -Condition ([string]::IsNullOrEmpty($state.GetCurrentMountPath())) -Message 'Reset did not clear the mount path.'
    Assert-Equal -Expected 0 -Actual $state.GetCurrentInventoryIndex() -Message 'Reset did not clear the inventory index.'
    Assert-True -Condition ($null -eq $state.GetCurrentWimIndexes()) -Message 'Reset did not clear WIM indexes.'
}

Invoke-Test 'driver metadata preserves inbox and boot-critical flags' {
    $driver = [InstalledDriverInfo]::new(@{
        PublishedName = 'oem1.inf'
        ClassName     = 'Custom'
        InboxDriver   = 'No'
        IsBootCritical = 'Yes'
    })
    Assert-True -Condition (-not $driver.IsInboxDriver) -Message 'Inbox=No was converted to true.'
    Assert-True -Condition $driver.IsBootCritical -Message 'DISM boot-critical flag was ignored.'
    Assert-True -Condition (-not $driver.CanBeRemoved) -Message 'Boot-critical driver was marked removable.'
}

Invoke-Test 'driver scanning honors the recursive checkbox' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'nested')) | Out-Null
    'Class=MEDIA' | Out-File -LiteralPath (Join-Path $tempRoot 'top.inf') -Encoding UTF8
    'Class=MEDIA' | Out-File -LiteralPath (Join-Path $tempRoot 'nested\nested.inf') -Encoding UTF8
    try {
        $topLevel = @(Get-DriversRecursive -RootPath $tempRoot -Recurse:$false)
        $recursive = @(Get-DriversRecursive -RootPath $tempRoot -Recurse:$true)
        Assert-Equal -Expected 1 -Actual $topLevel.Count -Message 'Non-recursive scan included nested drivers.'
        Assert-Equal -Expected 2 -Actual $recursive.Count -Message 'Recursive scan missed nested drivers.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'batch injection uses only the validated driver list' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'Windows')) | Out-Null
    $firstInf = Join-Path $tempRoot 'first.inf'
    $secondInf = Join-Path $tempRoot 'second.inf'
    'Class=MEDIA' | Out-File -LiteralPath $firstInf -Encoding UTF8
    'Class=MEDIA' | Out-File -LiteralPath $secondInf -Encoding UTF8
    $calls = [System.Collections.Generic.List[object]]::new()
    function Clear-MountDirectory { param([string]$MountPath) return $true }
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $calls.Add([PSCustomObject]@{ Operation = $Operation; Arguments = $Arguments })
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }

    try {
        $result = Invoke-SimpleBatchStyleProcessing -WimFilePath (Join-Path $tempRoot 'install.wim') -Index 1 -MountPath $tempRoot -Drivers @([DriverInfo]::new($firstInf))
        $add = $calls | Where-Object { $_.Operation -eq '/Add-Driver' } | Select-Object -First 1
        Assert-True -Condition $result -Message 'Batch injection failed in fixture.'
        Assert-True -Condition ($add.Arguments.Driver -contains $firstInf) -Message 'Validated driver was not passed to DISM.'
        Assert-True -Condition ($add.Arguments.Driver -notcontains $secondInf) -Message 'Unselected driver was injected.'
        Assert-True -Condition (-not $add.Arguments.Recurse) -Message 'Batch injection unexpectedly recursed through the folder.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'failed batch injection discards instead of committing' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'Windows')) | Out-Null
    $calls = [System.Collections.Generic.List[object]]::new()
    function Clear-MountDirectory { param([string]$MountPath) return $true }
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $calls.Add([PSCustomObject]@{ Operation = $Operation; Arguments = $Arguments })
        if ($Operation -eq '/Add-Driver') {
            return @{ Success = $false; StandardError = 'injection failed'; ExitCode = 1; TimedOut = $false }
        }
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }

    try {
        $batchInf = Join-Path $tempRoot 'batch.inf'
        'Class=MEDIA' | Out-File -LiteralPath $batchInf -Encoding UTF8
        $result = Invoke-SimpleBatchStyleProcessing -WimFilePath (Join-Path $tempRoot 'install.wim') -Index 1 -MountPath $tempRoot -Drivers @([DriverInfo]::new($batchInf))
        $unmount = $calls | Where-Object { $_.Operation -eq '/Unmount-Image' } | Select-Object -Last 1
        Assert-True -Condition (-not $result) -Message 'Failed injection reported success.'
        Assert-True -Condition ($null -ne $unmount -and $unmount.Arguments.Discard -and -not $unmount.Arguments.Commit) -Message 'Failed injection must be discarded, not committed.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'partial individual injection is discarded and reported as failure' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'Windows')) | Out-Null
    $firstInf = Join-Path $tempRoot 'first.inf'
    $secondInf = Join-Path $tempRoot 'second.inf'
    'Class=MEDIA' | Out-File -LiteralPath $firstInf -Encoding UTF8
    'Class=MEDIA' | Out-File -LiteralPath $secondInf -Encoding UTF8
    $drivers = @([DriverInfo]::new($firstInf), [DriverInfo]::new($secondInf))
    $calls = [System.Collections.Generic.List[object]]::new()
    function Clear-MountDirectory { param([string]$MountPath) return $true }
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $calls.Add([PSCustomObject]@{ Operation = $Operation; Arguments = $Arguments })
        if ($Operation -eq '/Add-Driver' -and $Arguments.Driver -like '*second.inf') {
            return @{ Success = $false; StandardError = 'second driver failed'; ExitCode = 1; TimedOut = $false }
        }
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }

    try {
        $result = Invoke-SimpleIndividualProcessing -WimFilePath (Join-Path $tempRoot 'install.wim') -Index 1 -MountPath $tempRoot -Drivers $drivers
        $unmount = $calls | Where-Object { $_.Operation -eq '/Unmount-Image' } | Select-Object -Last 1
        Assert-True -Condition (-not $result) -Message 'Partial driver injection reported success.'
        Assert-True -Condition ($null -ne $unmount -and $unmount.Arguments.Discard -and -not $unmount.Arguments.Commit) -Message 'Partial driver injection must be discarded.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'partial index success is not workflow success' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $infPath = Join-Path $tempRoot 'test.inf'
    'Class=MEDIA' | Out-File -LiteralPath $infPath -Encoding UTF8
    'MSWIM' | Out-File -LiteralPath (Join-Path $tempRoot 'install.wim') -Encoding ASCII
    $mountPath = Join-Path $tempRoot 'mount'
    [System.IO.Directory]::CreateDirectory($mountPath) | Out-Null
    function Get-WimIndexes { param([string]$WimFilePath) return @(1, 2) }
    function Invoke-SimpleIndividualProcessing {
        param([string]$WimFilePath, [int]$Index, [string]$MountPath, [DriverInfo[]]$Drivers, [switch]$ForceUnsigned)
        return ($Index -eq 1)
    }

    try {
        $result = Invoke-DriverInjectionWorkflow -WimFilePath (Join-Path $tempRoot 'install.wim') -SelectedDrivers @([DriverInfo]::new($infPath)) -MountDirectoryPath $mountPath -ForceUnsignedDrivers
        Assert-True -Condition (-not $result.Success) -Message 'Partial index success must not set workflow success.'
        Assert-Equal -Expected 1 -Actual $result.FailedIndexes -Message 'Failed index count is incorrect.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'driver export forwards the selected driver list' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $capturedArguments = $null
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $script:CapturedExportArguments = $Arguments
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }
    $driver = [InstalledDriverInfo]::new(@{ PublishedName = 'oem7.inf'; ClassName = 'Custom'; InboxDriver = $false })

    try {
        $result = Export-DriversFromMountedImage -MountPath $tempRoot -DestinationPath (Join-Path $tempRoot 'export') -DriversToExport @($driver)
        Assert-True -Condition $result.Success -Message 'Export failed in test fixture.'
        Assert-True -Condition ($null -ne $script:CapturedExportArguments -and $script:CapturedExportArguments.Driver -contains 'oem7.inf') -Message 'Selected driver list was not passed to DISM.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedExportArguments -Scope Script -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'removal workflow discards failed removals' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'Windows')) | Out-Null
    $calls = [System.Collections.Generic.List[object]]::new()
    function Clear-MountDirectory { param([string]$MountPath) return $true }
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $calls.Add([PSCustomObject]@{ Operation = $Operation; Arguments = $Arguments })
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }
    function Remove-DriversFromMountedImage {
        param([string]$MountPath, [InstalledDriverInfo[]]$DriversToRemove, [switch]$Force)
        return @{ Success = $false; SuccessfulRemovals = 0; FailedRemovals = 1; SkippedDrivers = 0 }
    }
    $driver = [InstalledDriverInfo]::new(@{ PublishedName = 'oem1.inf'; ClassName = 'Custom'; InboxDriver = $false })

    try {
        $result = Invoke-DriverRemovalWorkflow -WimFilePath (Join-Path $tempRoot 'install.wim') -Index 2 -MountPath $tempRoot -Drivers @($driver)
        $unmount = $calls | Where-Object { $_.Operation -eq '/Unmount-Image' } | Select-Object -Last 1
        Assert-True -Condition (-not $result.Success) -Message 'Failed removal workflow reported success.'
        Assert-True -Condition ($null -ne $unmount -and $unmount.Arguments.Discard -and -not $unmount.Arguments.Commit) -Message 'Failed removal was not discarded.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'export workflow honors index and selected drivers' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory((Join-Path $tempRoot 'Windows')) | Out-Null
    $calls = [System.Collections.Generic.List[object]]::new()
    function Clear-MountDirectory { param([string]$MountPath) return $true }
    function Invoke-EnhancedDismOperation {
        param([string]$Operation, [hashtable]$Arguments, [int]$TimeoutMs)
        $calls.Add([PSCustomObject]@{ Operation = $Operation; Arguments = $Arguments })
        return @{ Success = $true; StandardOutput = ''; StandardError = ''; ExitCode = 0; TimedOut = $false }
    }
    $driver = [InstalledDriverInfo]::new(@{ PublishedName = 'oem9.inf'; ClassName = 'Custom'; InboxDriver = $false })

    try {
        $result = Invoke-DriverExportWorkflow -WimFilePath (Join-Path $tempRoot 'install.wim') -Index 3 -MountPath $tempRoot -DestinationPath (Join-Path $tempRoot 'export') -Drivers @($driver)
        $mount = $calls | Where-Object { $_.Operation -eq '/Mount-Image' } | Select-Object -First 1
        $export = $calls | Where-Object { $_.Operation -eq '/Export-Driver' } | Select-Object -First 1
        $unmount = $calls | Where-Object { $_.Operation -eq '/Unmount-Image' } | Select-Object -Last 1
        Assert-True -Condition $result.Success -Message 'Export workflow failed in fixture.'
        Assert-Equal -Expected 3 -Actual $mount.Arguments.Index -Message 'Export mounted the wrong index.'
        Assert-True -Condition ($export.Arguments.Driver -contains 'oem9.inf') -Message 'Export ignored the selected driver.'
        Assert-True -Condition ($unmount.Arguments.Discard) -Message 'Export mount was not discarded.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'operation journal round-trips and clears stale state' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $journalPath = Join-Path $tempRoot 'operation.json'
    try {
        Write-OperationJournal -JournalPath $journalPath -MountPath 'C:\Temp\WIMDS-Test' -WimFilePath 'C:\Images\install.wim' -Index 2 -Phase 'Processing'
        $journal = Get-StaleOperationJournal -JournalPath $journalPath
        Assert-Equal -Expected 'C:\Temp\WIMDS-Test' -Actual $journal.MountPath -Message 'Journal mount path was not retained.'
        Assert-Equal -Expected 2 -Actual $journal.Index -Message 'Journal index was not retained.'
        Clear-OperationJournal -JournalPath $journalPath
        Assert-True -Condition ($null -eq (Get-StaleOperationJournal -JournalPath $journalPath)) -Message 'Journal was not cleared.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'operation journal is retained until owned mount cleanup succeeds' {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WIMDS-Test-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $journalPath = Join-Path $tempRoot 'operation.json'
    try {
        Write-OperationJournal -JournalPath $journalPath -MountPath $tempRoot -Phase 'Processing'
        $failed = Complete-OperationJournal -JournalPath $journalPath -MountPath $tempRoot
        Assert-True -Condition (-not $failed) -Message 'Unowned mount cleanup must not complete the journal.'
        Assert-True -Condition ($null -ne (Get-StaleOperationJournal -JournalPath $journalPath)) -Message 'Failed cleanup erased recovery evidence.'
        $noMount = Complete-OperationJournal -JournalPath $journalPath -MountPath ''
        Assert-True -Condition (-not $noMount) -Message 'A no-mount workflow must not erase another operation journal.'
        Assert-True -Condition ($null -ne (Get-StaleOperationJournal -JournalPath $journalPath)) -Message 'No-mount completion erased recovery evidence.'

        $mountPath = New-ApplicationMountDirectory -ParentPath $tempRoot
        Write-OperationJournal -JournalPath $journalPath -MountPath $mountPath -Phase 'Processing'
        $completed = Complete-OperationJournal -JournalPath $journalPath -MountPath $mountPath
        Assert-True -Condition $completed -Message 'Owned mount cleanup did not complete the journal.'
        Assert-True -Condition ($null -eq (Get-StaleOperationJournal -JournalPath $journalPath)) -Message 'Successful cleanup left a stale journal.'
        Assert-True -Condition (-not [System.IO.File]::Exists($journalPath + '.tmp')) -Message 'Atomic journal temporary file was left behind.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Test 'async workflow returns results and runs final cleanup' {
    Add-Type -AssemblyName PresentationFramework
    $script:AsyncWorkflowResult = $null
    $script:AsyncWorkflowFinally = $false
    $app = [System.Windows.Application]::new()
    $script:AsyncTestApplication = $app

    $handles = Start-AsyncPowerShellWorkflow -ScriptPath $ScriptPath -Workflow { return @{ Value = 42 } } -Variables @{} -BusyState 'Processing' -OnCompleted {
        param($Result)
        $script:AsyncWorkflowResult = $Result
        $script:AsyncTestApplication.Shutdown()
    } -OnFinally {
        $script:AsyncWorkflowFinally = $true
    }

    Assert-True -Condition ($null -ne $handles.Messages) -Message 'Async workflow message queue was not returned.'
    $timeoutTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $timeoutTimer.Interval = [TimeSpan]::FromSeconds(5)
    $timeoutTimer.Add_Tick({ $script:AsyncTestApplication.Shutdown() })
    $timeoutTimer.Start()
    $app.Run()
    $timeoutTimer.Stop()

    Assert-Equal -Expected 42 -Actual $script:AsyncWorkflowResult.Value -Message 'Async workflow result was not delivered.'
    Assert-True -Condition $script:AsyncWorkflowFinally -Message 'Async workflow final cleanup did not run.'
    Assert-True -Condition ($null -eq $script:ApplicationState.GetCurrentPowerShell()) -Message 'Async PowerShell handle was not cleared.'
}

Write-Host "Tests: $script:Passed passed, $script:Failed failed"
if ($script:Failed -gt 0) {
    exit 1
}
