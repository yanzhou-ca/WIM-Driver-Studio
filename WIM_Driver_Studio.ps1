<#
.SYNOPSIS
    WIM Driver Studio
    
.DESCRIPTION
    A comprehensive PowerShell application for injecting drivers into Windows Image (WIM) files
    with enterprise-grade security, performance optimization, Windows 11 Fluent Design UI,
    and full PowerShell 5.1 compatibility.
    
    This tool provides a secure, user-friendly interface for:
    - Selecting and validating WIM files (boot.wim, install.wim, etc.)
    - Scanning driver folders for .inf files with parallel processing
    - Injecting selected drivers into all WIM indexes
    - Real-time progress monitoring and detailed logging
    - Comprehensive error handling and recovery mechanisms
    
.PARAMETER None
    This is a GUI application that doesn't accept command-line parameters.
    All configuration is done through the user interface.
    
.INPUTS
    None. This script does not accept pipeline input.
    
.OUTPUTS
    GUI Application Window. Detailed logs are displayed in the UI and written to verbose stream.
    
.EXAMPLE
    .\WIM-Driver-Injection-Tool.ps1
    
    Launches the GUI application for interactive driver injection.
    
.EXAMPLE
    Start-Process PowerShell -ArgumentList "-File .\WIM-Driver-Injection-Tool.ps1" -Verb RunAs
    
    Launches the application with administrator privileges (recommended).
    
.NOTES
    Version: 1.0
    Author: Yan Zhou
    Requires: PowerShell 5.1+, Administrator privileges, DISM tool
    
    Compatibility: Tested and verified on Windows PowerShell 5.1
    Security: Enhanced input validation, secure process execution, path traversal protection
    Performance: Optimized with parallel processing and efficient UI updates
    
    SECURITY NOTICE:
    This tool requires administrator privileges and can modify system images.
    Only use with trusted driver packages and in secure environments.
#>

# Strict compatibility and security requirements
#Requires -Version 5.1
#Requires -RunAsAdministrator

#region 1. Core Initialization and Assembly Management
<#
.SYNOPSIS
    Initializes the application with proper error handling and DPI awareness.
    
.DESCRIPTION
    This region handles the critical initialization phase:
    - Loads required .NET assemblies with comprehensive error handling
    - Sets up DPI awareness for modern high-DPI displays
    - Configures performance settings for optimal UI responsiveness
    - Establishes secure execution environment
#>

try {
    Write-Verbose "Starting WIM Driver Studio..."
    Write-Verbose "Initializing required assemblies and system settings..."
    
    # Step 1: Load required .NET assemblies with comprehensive error handling
    $requiredAssemblies = @(
        'PresentationFramework',
        'PresentationCore',
        'WindowsBase',
        'System.Windows.Forms',
        'System.Security'
    )
    
    foreach ($assembly in $requiredAssemblies) {
        try {
            Add-Type -AssemblyName $assembly -ErrorAction Stop
            Write-Verbose "Successfully loaded assembly: $assembly"
        }
        catch {
            Write-Error "Failed to load required assembly '$assembly': $($_.Exception.Message)"
            throw "Critical assembly loading failure: $assembly"
        }
    }
    
    # Step 2: Scoped progress preference to avoid global impact
    $originalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    
    # Step 3: Enhanced DPI awareness setup for Windows 10/11 compatibility
    $dpiHelperCode = @"
using System;
using System.Runtime.InteropServices;

/// <summary>
/// Helper class for setting DPI awareness in PowerShell 5.1 compatible way
/// </summary>
public static class DpiHelper {
    [DllImport("shcore.dll", SetLastError = true)]
    public static extern int SetProcessDpiAwareness(int awareness);
    
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
    
    /// <summary>
    /// Sets appropriate DPI awareness based on Windows version
    /// </summary>
    /// <returns>True if DPI awareness was set successfully</returns>
    public static bool SetDpiAwareness() {
        try {
            // Try modern method first (Windows 8.1+)
            if (Environment.OSVersion.Version.Major >= 6 && 
                Environment.OSVersion.Version.Minor >= 3) {
                return SetProcessDpiAwareness(2) == 0; // PROCESS_PER_MONITOR_DPI_AWARE
            } else {
                return SetProcessDPIAware(); // Fallback for older Windows versions
            }
        } catch {
            return false; // Gracefully handle DPI awareness failures
        }
    }
}
"@
    
    # Only add the type if it doesn't already exist (prevents re-compilation errors)
    if (-not ([System.Management.Automation.PSTypeName]'DpiHelper').Type) {
        Add-Type -TypeDefinition $dpiHelperCode -ErrorAction SilentlyContinue
        Write-Verbose "DPI Helper class compiled successfully"
    }
    
    # Set DPI awareness with error handling
    $dpiResult = [DpiHelper]::SetDpiAwareness()
    Write-Verbose "DPI Awareness configured: $dpiResult"
    
    Write-Verbose "Core initialization completed successfully"
}
catch {
    Write-Error "Critical initialization failure: $($_.Exception.Message)"
    throw "Application cannot start due to initialization errors"
}
#endregion

#region 2. Type Definitions and Enumerations
<#
.SYNOPSIS
    Defines all enumerations and data structures used throughout the application.
    
.DESCRIPTION
    This region establishes the type system for the application:
    - Workflow step enumeration for UI state management
    - Logging levels for consistent message categorization
    - Driver signature status tracking for security
    - Processing state management for thread safety
    - Result classes for structured error handling
#>

# Make enums available globally by defining them in the global scope
if (-not ([System.Management.Automation.PSTypeName]'WorkflowStep').Type) {
    Add-Type -TypeDefinition @"
    public enum WorkflowStep {
        SelectWim = 1,      // Step 1: Select WIM file
        SelectDrivers = 2,  // Step 2: Choose driver packages  
        Configure = 3,      // Step 3: Configure injection options
        Process = 4         // Step 4: Execute driver injection
    }
"@
}

if (-not ([System.Management.Automation.PSTypeName]'LogLevel').Type) {
    Add-Type -TypeDefinition @"
    public enum LogLevel {
        Info,      // General information messages
        Warning,   // Non-critical issues that need attention
        Error,     // Critical errors that stop processing
        Success,   // Successful operation completion
        Debug      // Detailed debugging information
    }
"@
}

if (-not ([System.Management.Automation.PSTypeName]'DriverSignatureStatus').Type) {
    Add-Type -TypeDefinition @"
    public enum DriverSignatureStatus {
        Unknown,   // Signature status could not be determined
        Signed,    // Driver is digitally signed and verified
        Unsigned,  // Driver lacks digital signature
        Invalid    // Driver signature is present but invalid
    }
"@
}

if (-not ([System.Management.Automation.PSTypeName]'ProcessingState').Type) {
    Add-Type -TypeDefinition @"
    public enum ProcessingState {
        Idle,         // No operation in progress
        Scanning,     // Scanning for driver files
        Processing,   // Injecting drivers into WIM
        Cancelling,   // User-initiated cancellation in progress
        Completed,    // Operation completed successfully
        Failed        // Operation failed with errors
    }
"@
}

if (-not ([System.Management.Automation.PSTypeName]'WimImageType').Type) {
    Add-Type -TypeDefinition @"
    public enum WimImageType {
        Unknown = 0,   // Could not determine image type
        Boot = 1,      // boot.wim / Windows PE / Setup environment
        Install = 2    // install.wim / full Windows installation
    }
"@
}

Write-Verbose "Enhanced type definitions and enumerations loaded successfully"
#endregion

#region 3. Configuration and Security Constants
<#
.SYNOPSIS
    Establishes immutable configuration settings and security parameters including driver management.
    
.DESCRIPTION
    This region defines all configuration constants used throughout the application:
    - Timeout values for various operations
    - Progress calculation constants
    - Security validation parameters
    - DISM command definitions including driver management
    - Performance tuning parameters
    
    All values are carefully chosen for enterprise environments.
#>

# Immutable configuration object with comprehensive settings
$script:Configuration = [PSCustomObject]@{
    # Operation timeout settings (in milliseconds)
    DismOperationTimeoutMs        = 900000     # 15 minutes for DISM operations
    MountVerificationDelayMs      = 30000      # 30 seconds to verify mount completion
    MountPollingIntervalMs        = 250        # 250ms polling interval for mount verification
    QuickCleanupTimeoutMs         = 10000      # 10 seconds for quick cleanup operations
    AsyncCleanupTimeoutMs         = 15000      # 15 seconds for asynchronous cleanup
    DriverScanTimeoutMs           = 600000     # 10 minutes for driver scanning operations
    DriverInventoryTimeoutMs      = 300000     # 5 minutes for driver inventory operations
    DriverRemovalTimeoutMs        = 120000     # 2 minutes for individual driver removal

    # Progress calculation constants for UI updates
    InitializationProgress        = 10         # Progress after initialization
    IndexDetectionProgress        = 20         # Progress after WIM index detection
    ProcessingStartProgress       = 30         # Progress when processing begins
    ProcessingProgressRange       = 60         # Total progress range for processing
    DriverInventoryProgress       = 15         # Progress range for driver inventory
    DriverRemovalProgress         = 25         # Progress range for driver removal

    # Progress distribution per WIM index (percentages)
    IndexMountProgressPercent     = 0.2        # 20% for mounting each index
    IndexDriverProgressPercent    = 0.6        # 60% for driver injection per index
    IndexCommitProgressPercent    = 0.8        # 80% for committing changes per index
    IndexInventoryProgressPercent = 0.15     # 15% for driver inventory per index
    IndexRemovalProgressPercent   = 0.25       # 25% for driver removal per index

    # UI performance and threading settings
    CleanupMonitorIntervalMs      = 1000       # 1 second cleanup monitoring interval
    ProgressUpdateBatchSize       = 20         # Batch UI updates for performance
    ParallelProcessingThreshold   = 10         # Minimum drivers for parallel processing
    MaxParallelThreads            = [Math]::Min([Environment]::ProcessorCount, 8) # CPU-based threading
    DriverDisplayBatchSize        = 50         # Maximum drivers to display per batch

    # Output length limits for security and performance
    DismOutputMaxChars            = 500        # Maximum DISM output characters to display
    DismErrorMaxChars             = 250        # Maximum DISM error output to display

    # DISM command definitions (immutable for security)
    DismGetWimInfo                = '/Get-WimInfo'        # Command to read WIM information
    DismMountImage                = '/Mount-Image'        # Command to mount WIM index
    DismUnmountImage              = '/Unmount-Image'      # Command to unmount WIM index
    DismAddDriverBase             = '/Add-Driver'         # Base command for adding drivers
    DismAddDriverCommand          = '/Driver'             # Driver parameter for DISM
    DismGetDrivers                = '/Get-Drivers'        # Command to list installed drivers
    DismGetDriverInfo             = '/Get-DriverInfo'     # Command to get detailed driver info
    DismRemoveDriver              = '/Remove-Driver'      # Command to remove drivers
    DismExportDriver              = '/Export-Driver'      # Command to export drivers
    DismCleanupMountpoints        = '/Cleanup-Mountpoints' # Global cleanup command
    DismIndexFlag                 = '/Index:'             # Index specification flag
    DismMountDirFlag              = '/MountDir:'          # Mount directory flag
    DismRecurseFlag               = '/Recurse'            # Recursive driver search flag
    DismForceUnsignedFlag         = '/ForceUnsigned'      # Force unsigned driver flag
    DismCommitFlag                = '/Commit'             # Commit changes flag
    DismDiscardFlag               = '/Discard'            # Discard changes flag
    DismAllDriversFlag            = '/All'                # Include all drivers flag
    DismFormatTableFlag           = '/Format:Table'       # Table format output flag
    DismDestinationFlag           = '/Destination:'       # Export destination flag

    # Enhanced security parameters
    MaxPathLength                 = 260        # Maximum allowed path length
    MaxFilesDeletionThreshold     = 10         # Safety limit for file deletion operations
    AllowedFileExtensions         = @('.wim', '.esd') # Allowed WIM file extensions
    MaxDriversForRemoval          = 20         # Safety limit for batch driver removal
    
    # --- Driver Target Suitability Classification ---
    # Classes appropriate for boot.wim (Windows PE). PE only needs drivers to
    # reach storage and network during Setup. All other classes are excluded.
    BootWimAllowedClasses         = @(
        'net', 'NetClient', 'NetService', 'NetTrans',
        'SCSIAdapter', 'HDC', 'DiskDrive', 'Volume', 'SCSI',
        'USB', 'SDHost', 'USBFunctionController'
    )
    
    # Service binary names that identify a storage controller driver. Used to
    # pick storage controllers out of the ambiguous 'System' class for boot.wim.
    # Matched as '<name>.sys' with a word boundary to avoid false positives.
    StorageServicePatterns        = @(
        'storahci', 'stornvme', 'storufs', 'storport',
        'iastor', 'iastora', 'iastorac', 'iastorav', 'iastorv', 'iaStorV',
        'vmd', 'VMD', 'mvumis', 'percsas', 'percsas2i', 'percsas3i',
        'amdsata', 'amdsbs', 'amd_sata', 'amd_xata', 'nvme', 'nvmevmd',
        'megasas', 'megasas2i', 'megasas35i', 'megasr', 'mraid35x',
        'vsmraid', 'vstxraid', 'lsi_sas', 'lsi_scsi', 'elxstor', 'adp94xx',
        'adpahci', 'adpu320', 'arcsas', 'sisraid4', 'uliagpkx', 'viaide'
    )
    
    # --- CORRECTED SECTION START ---
    
    # Protected system paths (dynamically generated for security)
    # This list is now more specific to prevent blocking legitimate subdirectories of the root drive.
    ProtectedSystemPaths          = @(
        [Environment]::GetFolderPath('System'),
        [Environment]::GetFolderPath('Windows'), 
        [Environment]::GetFolderPath('ProgramFiles'),
        [Environment]::GetFolderPath('ProgramFilesX86')
    ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique # Ensure paths are clean and unique
    
    # --- CORRECTED SECTION END ---
    
    # Characters that pose security risks in paths
    DangerousPathChars            = @('"', '&', '|', ';', '<', '>', '^', '%', '`', '$', '~', [char]0)
    
    # Protected driver classes that cannot be removed
    ProtectedDriverClasses        = @(
        'System',
        'Computer',
        'Processor',
        'HDC',
        'DiskDrive',
        'Volume',
        'SCSI',
        'TapeDrive',
        'FloppyDisk'
    )
}

# Pre-compiled regex patterns for performance optimization
$script:SensitiveDataPatterns = @(
    [regex]::new('(?i)password\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)pwd\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)key\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)token\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)secret\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)auth\s*[=:]\s*\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled),
    [regex]::new('(?i)bearer\s+\S+', [System.Text.RegularExpressions.RegexOptions]::Compiled)
)

# Driver inventory parsing patterns
$script:DriverOutputPatterns = @{
    PublishedName    = [regex]::new('Published Name\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    OriginalFileName = [regex]::new('Original File Name\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    ClassName        = [regex]::new('Class Name\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    ProviderName     = [regex]::new('Provider Name\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    DriverDate       = [regex]::new('Driver Date\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    DriverVersion    = [regex]::new('Driver Version\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    InboxDriver      = [regex]::new('Inbox\s*:\s*(.+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

Write-Verbose "Enhanced configuration and security constants with driver management initialized successfully"
#endregion

#region 4. Enhanced Data Classes and Validation
<#
.SYNOPSIS
    Simplified data classes for structured error handling and data management including driver inventory.
#>

class ValidationResult {
    [bool]$IsValid
    [string]$ErrorMessage
    [string]$ResolvedPath
    [hashtable]$AdditionalData
    
    ValidationResult([bool]$isValid, [string]$errorMessage, [string]$resolvedPath) {
        $this.IsValid = $isValid
        $this.ErrorMessage = $errorMessage
        $this.ResolvedPath = $resolvedPath
        $this.AdditionalData = @{}
    }
    
    static [ValidationResult] Success([string]$resolvedPath) {
        return [ValidationResult]::new($true, $null, $resolvedPath)
    }
    
    static [ValidationResult] Failure([string]$errorMessage) {
        return [ValidationResult]::new($false, $errorMessage, $null)
    }
    
    [void] AddData([string]$key, [object]$value) {
        $this.AdditionalData[$key] = $value
    }
}

class WorkflowResult {
    [bool]$Success
    [string]$Message
    [string]$Details
    [hashtable]$ErrorInfo
    [int]$ProcessedIndexes
    [int]$SuccessfulIndexes
    [int]$FailedIndexes
    [int]$DriversInventoried
    [int]$DriversRemoved
    [timespan]$Duration
    
    WorkflowResult() {
        $this.Success = $false
        $this.ErrorInfo = @{}
        $this.Duration = [timespan]::Zero
        $this.ProcessedIndexes = 0
        $this.SuccessfulIndexes = 0
        $this.FailedIndexes = 0
        $this.DriversInventoried = 0
        $this.DriversRemoved = 0
    }
}

class DriverInfo {
    [string]$FileName
    [string]$FilePath
    [string]$FullPath
    [string]$Name
    [string]$Version
    [string]$Manufacturer
    [string]$Date
    [string]$SignatureStatus
    [string]$Architecture
    [string]$Description
    [string]$Hash
    [long]$Size
    [DateTime]$LastModified
    
    DriverInfo([string]$infFilePath) {
        $this.FilePath = $infFilePath
        $this.FullPath = [System.IO.Path]::GetFullPath($infFilePath)
        $this.FileName = [System.IO.Path]::GetFileNameWithoutExtension($infFilePath)
        $this.Initialize()
    }
    
    [void] Initialize() {
        try {
            if ([System.IO.File]::Exists($this.FullPath)) {
                $fileInfo = [System.IO.FileInfo]::new($this.FullPath)
                $this.Size = $fileInfo.Length
                $this.LastModified = $fileInfo.LastWriteTime
                
                # Parse INF content first to get driver information
                $this.ParseInfContent()
                
                # Then verify signature (this is more comprehensive now)
                $this.VerifySignature()
                
                # Compute hash last for file integrity
                $this.ComputeHash()
            }
        }
        catch {
            # Set safe defaults on initialization failure
            $this.Name = $this.FileName
            $this.Version = "Unknown"
            $this.Manufacturer = "Unknown"
            $this.Date = "Unknown"
            $this.Architecture = "Unknown"
            $this.Description = "Initialization Failed"
            $this.Hash = "Error"
            $this.SignatureStatus = "Unknown"
        }
    }
    
    [void] ComputeHash() {
        try {
            $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
            $fileStream = [System.IO.File]::OpenRead($this.FullPath)
            $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
            $this.Hash = [System.BitConverter]::ToString($hashBytes).Replace('-', '')
            $fileStream.Dispose()
            $hashAlgorithm.Dispose()
        }
        catch {
            $this.Hash = "Error"
        }
    }
    
    [void] ParseInfContent() {
        try {
            $content = [System.IO.File]::ReadAllLines($this.FullPath)
            
            $this.Name = $this.FileName
            $this.Version = "Unknown"
            $this.Manufacturer = "Unknown"
            $this.Date = "Unknown"
            $this.Architecture = "Unknown"
            $this.Description = ""
            
            foreach ($line in $content) {
                $line = $line.Trim()
                
                if ($line.StartsWith(";") -or [string]::IsNullOrWhiteSpace($line)) {
                    continue
                }
                
                if ($line -match "^DriverVer\s*=\s*(.+)") {
                    $versionInfo = $matches[1].Split(',')
                    if ($versionInfo.Length -ge 1) { $this.Date = $versionInfo[0].Trim() }
                    if ($versionInfo.Length -ge 2) { $this.Version = $versionInfo[1].Trim() }
                }
                elseif ($line -match "^Provider\s*=\s*(.+)") {
                    $this.Manufacturer = $matches[1].Trim().Trim('"', '%')
                }
                elseif ($line -match "^Class\s*=\s*(.+)") {
                    $this.Description = $matches[1].Trim().Trim('"')
                }
                elseif ($line -match "^DriverDesc\s*=\s*(.+)") {
                    $this.Name = $matches[1].Trim().Trim('"', '%')
                }
                elseif ($line -match "TargetOSVersion.*\.(x64|amd64|x86|arm64)") {
                    $this.Architecture = $matches[1].ToUpper()
                }
            }
        }
        catch {
            Write-Warning "Failed to parse INF content for '$($this.FullPath)'"
        }
    }
    
    [void] VerifySignature() {
        try {
            # First, try to check the INF file itself (some newer packages sign the INF)
            try {
                $infSignature = Get-AuthenticodeSignature -FilePath $this.FullPath -ErrorAction Stop
                if ($infSignature.Status -eq 'Valid') {
                    $this.SignatureStatus = 'Signed'
                    return
                }
            }
            catch { }
            
            # For driver packages, check for catalog files or signed sys files in the same directory
            $driverDir = [System.IO.Path]::GetDirectoryName($this.FullPath)
            $infName = [System.IO.Path]::GetFileNameWithoutExtension($this.FullPath)
            
            # Look for catalog file with same name as INF
            $catFile = [System.IO.Path]::Combine($driverDir, "$infName.cat")
            if ([System.IO.File]::Exists($catFile)) {
                try {
                    $catSignature = Get-AuthenticodeSignature -FilePath $catFile -ErrorAction Stop
                    if ($catSignature.Status -eq 'Valid') {
                        $this.SignatureStatus = 'Signed'
                        return
                    }
                }
                catch { }
            }
            
            # Look for any .cat files in the same directory
            try {
                $catFiles = [System.IO.Directory]::GetFiles($driverDir, "*.cat")
                foreach ($cat in $catFiles) {
                    try {
                        $catSignature = Get-AuthenticodeSignature -FilePath $cat -ErrorAction Stop
                        if ($catSignature.Status -eq 'Valid') {
                            $this.SignatureStatus = 'Signed'
                            return
                        }
                    }
                    catch { }
                }
            }
            catch { }
            
            # Look for signed .sys files mentioned in the INF
            try {
                $infContent = [System.IO.File]::ReadAllText($this.FullPath)
                $sysMatches = [regex]::Matches($infContent, '(\w+\.sys)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                
                foreach ($match in $sysMatches) {
                    $sysFile = [System.IO.Path]::Combine($driverDir, $match.Groups[1].Value)
                    if ([System.IO.File]::Exists($sysFile)) {
                        try {
                            $sysSignature = Get-AuthenticodeSignature -FilePath $sysFile -ErrorAction Stop
                            if ($sysSignature.Status -eq 'Valid') {
                                $this.SignatureStatus = 'Signed'
                                return
                            }
                        }
                        catch { }
                    }
                }
                
                # Also check for .dll files that might be signed
                $dllMatches = [regex]::Matches($infContent, '(\w+\.dll)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($match in $dllMatches) {
                    $dllFile = [System.IO.Path]::Combine($driverDir, $match.Groups[1].Value)
                    if ([System.IO.File]::Exists($dllFile)) {
                        try {
                            $dllSignature = Get-AuthenticodeSignature -FilePath $dllFile -ErrorAction Stop
                            if ($dllSignature.Status -eq 'Valid') {
                                $this.SignatureStatus = 'Signed'
                                return
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            
            # If no signed files found, mark as unsigned
            $this.SignatureStatus = 'Unsigned'
        }
        catch {
            $this.SignatureStatus = 'Unknown'
        }
    }
    
    [string] GetSizeFormatted() {
        if ($this.Size -gt 1MB) {
            $sizeMB = [math]::Round($this.Size / 1MB, 1)
            return "$sizeMB MB"
        }
        else {
            $sizeKB = [math]::Round($this.Size / 1KB, 1)
            return "$sizeKB KB"
        }
    }
    
    [bool] IsSigned() {
        return $this.SignatureStatus -eq 'Signed'
    }
}

class InstalledDriverInfo {
    [string]$PublishedName
    [string]$OriginalFileName
    [string]$ClassName
    [string]$ClassGuid
    [string]$ProviderName
    [string]$DriverDate
    [string]$DriverVersion
    [bool]$IsInboxDriver
    [bool]$IsBootCritical
    [bool]$CanBeRemoved
    [string]$Status
    [string]$Architecture
    [long]$Size
    [string]$Description
    
    InstalledDriverInfo() {
        $this.Status = "Unknown"
        $this.CanBeRemoved = $false
        $this.IsBootCritical = $false
        $this.IsInboxDriver = $false
        $this.Size = 0
    }
    
    InstalledDriverInfo([hashtable]$properties) {
        $this.PublishedName = if ($null -ne $properties.PublishedName) { $properties.PublishedName } else { "Unknown" }
        $this.OriginalFileName = if ($null -ne $properties.OriginalFileName) { $properties.OriginalFileName } else { "Unknown" }
        $this.ClassName = if ($null -ne $properties.ClassName) { $properties.ClassName } else { "Unknown" }
        $this.ClassGuid = if ($null -ne $properties.ClassGuid) { $properties.ClassGuid } else { "" }
        $this.ProviderName = if ($null -ne $properties.ProviderName) { $properties.ProviderName } else { "Unknown" }
        $this.DriverDate = if ($null -ne $properties.DriverDate) { $properties.DriverDate } else { "Unknown" }
        $this.DriverVersion = if ($null -ne $properties.DriverVersion) { $properties.DriverVersion } else { "Unknown" }
        $this.IsInboxDriver = if ($null -ne $properties.InboxDriver) { [bool]$properties.InboxDriver } else { $false }
        $this.IsBootCritical = $this.DetermineBootCritical()
        $this.CanBeRemoved = $this.DetermineRemovability()
        $this.Status = if ($null -ne $properties.Status) { $properties.Status } else { "Installed" }
        $this.Architecture = if ($null -ne $properties.Architecture) { $properties.Architecture } else { "Unknown" }
        $this.Size = if ($null -ne $properties.Size) { [long]$properties.Size } else { [long]0 }
        $this.Description = if ($null -ne $properties.Description) { $properties.Description } else { $this.ClassName }
    }
    
    [bool] DetermineBootCritical() {
        if ($this.IsInboxDriver) {
            return $true
        }
        
        $bootCriticalClasses = @(
            'System', 'Computer', 'Processor', 'HDC', 'DiskDrive', 
            'Volume', 'SCSI', 'TapeDrive', 'FloppyDisk', 'SCSIAdapter'
        )
        
        return $this.ClassName -in $bootCriticalClasses
    }
    
    [bool] DetermineRemovability() {
        if ($this.IsInboxDriver -or $this.IsBootCritical) {
            return $false
        }
        
        if ($this.ProviderName -eq "Microsoft Corporation" -and $this.IsInboxDriver) {
            return $false
        }
        
        return $true
    }
    
    [string] GetFormattedDate() {
        try {
            if ($this.DriverDate -match '\d{1,2}/\d{1,2}/\d{4}') {
                $date = [DateTime]::Parse($this.DriverDate)
                return $date.ToString("yyyy-MM-dd")
            }
            return $this.DriverDate
        }
        catch {
            return $this.DriverDate
        }
    }
    
    [string] GetSizeFormatted() {
        if ($this.Size -gt 1MB) {
            $sizeMB = [math]::Round($this.Size / 1MB, 1)
            return "$sizeMB MB"
        }
        elseif ($this.Size -gt 1KB) {
            $sizeKB = [math]::Round($this.Size / 1KB, 1)
            return "$sizeKB KB"
        }
        else {
            return "$($this.Size) B"
        }
    }
    
    [string] GetStatusIcon() {
        if (-not $this.CanBeRemoved) {
            return "[P]"  # Locked/protected
        }
        elseif ($this.IsInboxDriver) {
            return "[B]"  # Inbox driver
        }
        elseif ($this.ProviderName -eq "Microsoft Corporation") {
            return "[M]"  # Microsoft driver
        }
        else {
            return "[D]"  # Third-party driver
        }
    }
    
    [string] GetRemovalStatusText() {
        if ($this.IsBootCritical) {
            return "Boot Critical - Cannot Remove"
        }
        elseif ($this.IsInboxDriver) {
            return "Inbox Driver - Cannot Remove"
        }
        elseif (-not $this.CanBeRemoved) {
            return "Protected - Cannot Remove"
        }
        else {
            return "Can be Removed"
        }
    }
}

class DriverManagementOperation {
    [string]$OperationType
    [string]$TargetWimPath
    [int]$TargetIndex
    [string]$MountPath
    [System.Collections.Generic.List[InstalledDriverInfo]]$SelectedDrivers
    [DateTime]$StartTime
    [DateTime]$EndTime
    [bool]$Success
    [string]$ErrorMessage
    [System.Collections.Generic.List[string]]$ProcessedDrivers
    [System.Collections.Generic.List[string]]$FailedDrivers
    
    DriverManagementOperation([string]$operationType) {
        $this.OperationType = $operationType
        $this.SelectedDrivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        $this.ProcessedDrivers = [System.Collections.Generic.List[string]]::new()
        $this.FailedDrivers = [System.Collections.Generic.List[string]]::new()
        $this.Success = $false
    }
    
    [void] Start() {
        $this.StartTime = [DateTime]::Now
    }
    
    [void] Complete([bool]$success, [string]$errorMessage = "") {
        $this.EndTime = [DateTime]::Now
        $this.Success = $success
        $this.ErrorMessage = $errorMessage
    }
    
    [timespan] GetDuration() {
        if ($this.EndTime -and $this.StartTime) {
            return $this.EndTime - $this.StartTime
        }
        elseif ($this.StartTime) {
            return [DateTime]::Now - $this.StartTime
        }
        else {
            return [timespan]::Zero
        }
    }
    
    [string] GetSummary() {
        $duration = $this.GetDuration()
        $summary = @"
Operation: $($this.OperationType)
Duration: $($duration.ToString("mm\:ss"))
Selected Drivers: $($this.SelectedDrivers.Count)
Processed Successfully: $($this.ProcessedDrivers.Count)
Failed: $($this.FailedDrivers.Count)
Overall Success: $($this.Success)
"@
        
        if (-not [string]::IsNullOrWhiteSpace($this.ErrorMessage)) {
            $summary += "`nError: $($this.ErrorMessage)"
        }
        
        return $summary
    }
}

class ThreadSafeApplicationState {
    [object] $syncRoot = [object]::new()
    [string] $_currentState = 'Idle'
    [System.Management.Automation.PowerShell] $_currentPowerShell
    [System.Management.Automation.Runspaces.Runspace] $_currentRunspace
    [System.Diagnostics.Process] $_currentProcess
    [System.Management.Automation.PSEventSubscriber] $_eventSubscription
    [System.IAsyncResult] $_backgroundResult
    [System.Collections.ArrayList] $DiscoveredDrivers
    [System.Collections.ArrayList] $InstalledDrivers
    [DriverManagementOperation] $_currentOperation
    
    ThreadSafeApplicationState() {
        $this.DiscoveredDrivers = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
        $this.InstalledDrivers = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    }

    [string] GetCurrentState() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._currentState 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetCurrentState([string]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._currentState = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [System.Diagnostics.Process] GetCurrentProcess() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._currentProcess 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetCurrentProcess([System.Diagnostics.Process]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._currentProcess = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }

    [System.Management.Automation.PowerShell] GetCurrentPowerShell() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._currentPowerShell 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetCurrentPowerShell([System.Management.Automation.PowerShell]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._currentPowerShell = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }

    [System.Management.Automation.Runspaces.Runspace] GetCurrentRunspace() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._currentRunspace 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetCurrentRunspace([System.Management.Automation.Runspaces.Runspace]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._currentRunspace = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [System.Management.Automation.PSEventSubscriber] GetEventSubscription() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._eventSubscription 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetEventSubscription([System.Management.Automation.PSEventSubscriber]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._eventSubscription = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [System.IAsyncResult] GetBackgroundResult() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._backgroundResult 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetBackgroundResult([System.IAsyncResult]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._backgroundResult = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }

    [DriverManagementOperation] GetCurrentOperation() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            return $this._currentOperation 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }
    
    [void] SetCurrentOperation([DriverManagementOperation]$value) {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try { 
            $this._currentOperation = $value 
        }
        finally { 
            [System.Threading.Monitor]::Exit($this.syncRoot) 
        }
    }

    [bool] IsProcessing() {
        $state = $this.GetCurrentState()
        return $state -in @('Scanning', 'Processing', 'InventoryingDrivers', 'RemovingDrivers')
    }
    
    [bool] CanCancel() {
        $state = $this.GetCurrentState()
        return $state -in @('Scanning', 'Processing', 'InventoryingDrivers', 'RemovingDrivers')
    }
    
    [void] Reset() {
        [System.Threading.Monitor]::Enter($this.syncRoot)
        try {
            $this._currentState = 'Idle'
            $this._currentPowerShell = $null
            $this._currentRunspace = $null
            $this._currentProcess = $null
            $this._eventSubscription = $null
            $this._backgroundResult = $null
            $this._currentOperation = $null
        }
        finally {
            [System.Threading.Monitor]::Exit($this.syncRoot)
        }
    }
}

Write-Verbose "Enhanced data classes with driver management initialized successfully"
#endregion

#region 5. Global State Management
<#
.SYNOPSIS
    Initializes global application state variables.
    
.DESCRIPTION
    This region establishes the global state management:
    - Thread-safe application state container
    - Main window reference for UI operations
    - Shared state accessible across all functions
#>

# Initialize global application state with thread safety
$script:ApplicationState = [ThreadSafeApplicationState]::new()
$script:MainWindow = $null
$script:LastProgressUpdate = [DateTime]::MinValue

# Driver-target suitability state: set when the user selects a WIM file.
# Used to partition discovered drivers into suitable / not-recommended groups.
$script:CurrentWimImageType = [WimImageType]::Unknown
$script:CurrentWimArchitecture = 'Unknown'

Write-Verbose "Global state management initialized"
#endregion

#region 6. Enhanced Security and Validation Functions
<#
.SYNOPSIS
    Comprehensive security validation and input sanitization functions.
    
.DESCRIPTION
    This region implements robust security measures:
    - Path traversal attack prevention
    - Input validation and sanitization
    - Privilege verification
    - File integrity checking
    - System requirement validation
#>

<#
.SYNOPSIS
    Performs comprehensive security validation of file system paths.
    
.DESCRIPTION
    Validates paths against various security threats including:
    - Path traversal attacks (../, ..\)
    - Null byte injection
    - Reserved character usage
    - Symbolic link targeting protected directories
    - Unicode normalization attacks
    
.PARAMETER Path
    The file system path to validate
    
.PARAMETER AllowRelative
    Whether to allow relative paths (default: false for security)
    
.OUTPUTS
    ValidationResult object with security validation outcome
#>
function Test-SecurePath {
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowRelative
    )
    
    begin {
        Write-Verbose "Validating path security: $Path"
    }
    
    process {
        try {
            # Step 1: Unicode normalization to prevent bypass attacks
            $normalizedPath = $Path.Normalize([System.Text.NormalizationForm]::FormC)
            
            # Step 2: Length validation to prevent buffer overflow attacks
            if ($normalizedPath.Length -gt $script:Configuration.MaxPathLength) {
                return [ValidationResult]::Failure("Path exceeds maximum allowed length of $($script:Configuration.MaxPathLength) characters")
            }
            
            # Step 3: Null byte injection protection
            if ($normalizedPath.Contains([char]0)) {
                return [ValidationResult]::Failure("Path contains null byte characters which are forbidden for security")
            }
            
            # Step 4: Dangerous character validation to prevent command injection
            foreach ($char in $script:Configuration.DangerousPathChars) {
                if ($normalizedPath.Contains($char)) {
                    return [ValidationResult]::Failure("Path contains dangerous character '$char' which poses security risks")
                }
            }
            
            # Step 5: Path traversal attack prevention
            if ($normalizedPath -match '\.\.[/\\]' -or $normalizedPath -match '[/\\]\.\.' -or $normalizedPath -eq '..') {
                return [ValidationResult]::Failure("Path contains directory traversal sequences which are forbidden for security")
            }
            
            # Step 6: Resolve to absolute path for consistency
            try {
                $resolvedPath = [System.IO.Path]::GetFullPath($normalizedPath)
            }
            catch [System.ArgumentException] {
                return [ValidationResult]::Failure("Path format is invalid or contains illegal characters")
            }
            catch [System.Security.SecurityException] {
                return [ValidationResult]::Failure("Access to the specified path is denied by security policy")
            }
            
            # --- CORRECTED SECTION START ---

            # Step 7: Protected system directory validation with more precise logic
            foreach ($protectedPath in $script:Configuration.ProtectedSystemPaths) {
                # Check for an exact match or if the path is a true sub-directory of a protected path.
                # This prevents blocking paths like 'C:\WindowsFoo' just because it starts with 'C:\Windows'.
                if ($resolvedPath.Equals($protectedPath, [StringComparison]::OrdinalIgnoreCase) -or `
                        $resolvedPath.StartsWith($protectedPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    return [ValidationResult]::Failure("Cannot access protected system directory: $protectedPath")
                }
            }
            
            # Step 8: Enhanced symbolic link resolution and validation
            if ([System.IO.File]::Exists($resolvedPath) -or [System.IO.Directory]::Exists($resolvedPath)) {
                try {
                    $item = Get-Item $resolvedPath -Force -ErrorAction Stop
                    if ($item.PSObject.Properties['LinkType'] -and $item.LinkType -eq 'SymbolicLink') {
                        $targetPath = $item.Target
                        if ($targetPath) {
                            # Validate symbolic link target against protected paths using the same precise logic
                            foreach ($protectedPath in $script:Configuration.ProtectedSystemPaths) {
                                if ($targetPath.Equals($protectedPath, [StringComparison]::OrdinalIgnoreCase) -or `
                                        $targetPath.StartsWith($protectedPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
                                    return [ValidationResult]::Failure("Symbolic link target points to protected directory: $protectedPath")
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not resolve symbolic link properties: $($_.Exception.Message)"
                }
            }
            
            # --- CORRECTED SECTION END ---

            # Step 9: Relative path validation if not allowed
            if (-not $AllowRelative -and -not [System.IO.Path]::IsPathRooted($normalizedPath)) {
                return [ValidationResult]::Failure("Relative paths are not allowed for security reasons")
            }
            
            return [ValidationResult]::Success($resolvedPath)
        }
        catch [System.ArgumentException] {
            return [ValidationResult]::Failure("Path format is invalid: $($_.Exception.Message)")
        }
        catch [System.UnauthorizedAccessException] {
            return [ValidationResult]::Failure("Access denied to the specified path")
        }
        catch [System.Security.SecurityException] {
            return [ValidationResult]::Failure("Security policy prevents access to the specified path")
        }
        catch {
            Write-Error "Unexpected error during path validation: $($_.Exception.Message)"
            return [ValidationResult]::Failure("Unexpected validation error occurred")
        }
    }
}

<#
.SYNOPSIS
    Verifies that the current process has enhanced administrator privileges.
    
.DESCRIPTION
    Performs comprehensive administrator privilege verification including:
    - Windows built-in administrator role membership
    - Elevated token verification
    - Security context validation
    
.OUTPUTS
    Boolean indicating whether enhanced administrator privileges are available
#>
function Test-EnhancedAdministratorPrivileges {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    process {
        try {
            Write-Verbose "Verifying enhanced administrator privileges..."
            
            # Get current Windows identity and security principal
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [System.Security.Principal.WindowsPrincipal]::new($currentUser)
            
            # Verify administrator role membership
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if ($isAdmin) {
                Write-Verbose "Enhanced administrator privileges confirmed for user: $($currentUser.Name)"
            }
            else {
                Write-Warning "Administrator privileges not available for user: $($currentUser.Name)"
            }
            
            return $isAdmin
        }
        catch {
            Write-Warning "Failed to verify administrator privileges: $($_.Exception.Message)"
            return $false
        }
    }
}

<#
.SYNOPSIS
    Validates WIM file integrity and format compliance.
    
.DESCRIPTION
    Performs comprehensive WIM file validation including:
    - Path security verification
    - File existence and accessibility
    - File extension validation
    - File size reasonableness checks
    - WIM file signature verification
    - Basic corruption detection
    
.PARAMETER WimPath
    Path to the WIM file to validate
    
.OUTPUTS
    ValidationResult with detailed validation outcome and metadata
#>
function Test-WimFileValidation {
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WimPath
    )
    
    process {
        try {
            Write-Verbose "Performing comprehensive WIM file validation for: $WimPath"
            
            # Step 1: Security path validation
            $pathValidation = Test-SecurePath -Path $WimPath
            if (-not $pathValidation.IsValid) {
                return [ValidationResult]::Failure("Path security validation failed: $($pathValidation.ErrorMessage)")
            }
            
            $securePath = $pathValidation.ResolvedPath
            
            # Step 2: File existence verification
            if (-not [System.IO.File]::Exists($securePath)) {
                return [ValidationResult]::Failure("WIM file does not exist at path: $securePath")
            }
            
            # Step 3: File extension validation
            $extension = [System.IO.Path]::GetExtension($securePath).ToLowerInvariant()
            if ($extension -notin $script:Configuration.AllowedFileExtensions) {
                return [ValidationResult]::Failure("File extension '$extension' is not supported. Allowed extensions: $($script:Configuration.AllowedFileExtensions -join ', ')")
            }
            
            # Step 4: File size reasonableness check
            try {
                $fileInfo = [System.IO.FileInfo]::new($securePath)
                if ($fileInfo.Length -lt 1MB) {
                    return [ValidationResult]::Failure("WIM file appears too small (less than 1MB) and may be corrupted")
                }
                
                # Check for extremely large files that might cause issues
                if ($fileInfo.Length -gt 50GB) {
                    Write-Warning "WIM file is very large (>50GB). Processing may take significant time and resources."
                }
            }
            catch [System.UnauthorizedAccessException] {
                return [ValidationResult]::Failure("Access denied when reading WIM file properties")
            }
            catch [System.IO.IOException] {
                return [ValidationResult]::Failure("I/O error when accessing WIM file")
            }
            
            # Step 5: WIM file signature verification
            try {
                $buffer = New-Object byte[] 8
                $fileStream = [System.IO.File]::OpenRead($securePath)
                try {
                    $bytesRead = $fileStream.Read($buffer, 0, 8)
                    if ($bytesRead -ge 5) {
                        $signature = [System.Text.Encoding]::ASCII.GetString($buffer, 0, 5)
                        if ($signature -ne "MSWIM") {
                            return [ValidationResult]::Failure("Invalid WIM file signature. File may be corrupted or not a valid WIM image.")
                        }
                    }
                    else {
                        return [ValidationResult]::Failure("Could not read sufficient data to verify WIM file signature")
                    }
                }
                finally {
                    $fileStream.Dispose()
                }
            }
            catch [System.UnauthorizedAccessException] {
                return [ValidationResult]::Failure("Access denied when reading WIM file for signature verification")
            }
            catch [System.IO.IOException] {
                return [ValidationResult]::Failure("I/O error when verifying WIM file signature")
            }
            
            # Step 6: Create successful validation result with metadata
            $result = [ValidationResult]::Success($securePath)
            $result.AddData('FileSize', $fileInfo.Length)
            $result.AddData('FileSizeFormatted', "{0:N2} GB" -f ($fileInfo.Length / 1GB))
            $result.AddData('LastModified', $fileInfo.LastWriteTime)
            $result.AddData('Extension', $extension)
            
            Write-Verbose "WIM file validation completed successfully"
            return $result
        }
        catch {
            return [ValidationResult]::Failure("Unexpected error during WIM file validation: $($_.Exception.Message)")
        }
    }
}

<#
.SYNOPSIS
    Validates driver folder accessibility and content.
    
.DESCRIPTION
    Performs comprehensive driver folder validation including:
    - Path security verification
    - Directory existence and accessibility
    - INF file presence detection
    - Recursive search capability verification
    
.PARAMETER DriverPath
    Path to the driver folder to validate
    
.OUTPUTS
    ValidationResult with validation outcome and driver count metadata
#>

<#
.SYNOPSIS
    Validates that a mount path meets DISM's file system prerequisites.
    
.DESCRIPTION
    Verifies that the target mount path is on a volume that is:
    - A local, fixed disk (not network, removable, etc.)
    - Formatted with NTFS
    - Ready and accessible
    
.PARAMETER MountPath
    The directory path to validate for mounting operations.
    
.OUTPUTS
    ValidationResult with the outcome of the prerequisite check.
#>
function Test-MountPathPrerequisites {
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountPath
    )

    process {
        try {
            Write-Verbose "Validating mount path prerequisites for: $MountPath"

            $fullPath = [System.IO.Path]::GetFullPath($MountPath)
            $driveLetter = [System.IO.Path]::GetPathRoot($fullPath).TrimEnd('\')
            
            $driveInfo = [System.IO.DriveInfo]::new($driveLetter)

            if (-not $driveInfo.IsReady) {
                return [ValidationResult]::Failure("The drive '$driveLetter' is not ready. Please ensure it is accessible.")
            }

            if ($driveInfo.DriveType -ne [System.IO.DriveType]::Fixed) {
                return [ValidationResult]::Failure("DISM requires a local fixed drive for mounting. The drive '$driveLetter' is of type '$($driveInfo.DriveType)'. Please choose a directory on a local hard disk (like C:).")
            }

            if ($driveInfo.DriveFormat -ne 'NTFS') {
                return [ValidationResult]::Failure("DISM requires an NTFS-formatted drive for mounting. The drive '$driveLetter' is formatted with '$($driveInfo.DriveFormat)'. Please choose a directory on an NTFS volume.")
            }
            
            Write-Verbose "Mount path prerequisites validated successfully."
            return [ValidationResult]::Success($fullPath)
        }
        catch [System.IO.DriveNotFoundException] {
            return [ValidationResult]::Failure("The drive specified in the mount path '$MountPath' could not be found.")
        }
        catch {
            return [ValidationResult]::Failure("An unexpected error occurred while validating the mount path drive: $($_.Exception.Message)")
        }
    }
}

function Test-DriverFolderValidation {
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DriverPath
    )
    
    process {
        try {
            Write-Verbose "Validating driver folder: $DriverPath"
            
            # Step 1: Security path validation
            $pathValidation = Test-SecurePath -Path $DriverPath
            if (-not $pathValidation.IsValid) {
                return [ValidationResult]::Failure("Path security validation failed: $($pathValidation.ErrorMessage)")
            }
            
            $securePath = $pathValidation.ResolvedPath
            
            # Step 2: Directory existence verification
            if (-not [System.IO.Directory]::Exists($securePath)) {
                return [ValidationResult]::Failure("Driver folder does not exist at path: $securePath")
            }
            
            # Step 3: Directory accessibility and INF file detection
            try {
                $directoryInfo = [System.IO.DirectoryInfo]::new($securePath)
                
                # Search for INF files in current directory and subdirectories
                $infFiles = @($directoryInfo.GetFiles("*.inf", [System.IO.SearchOption]::AllDirectories))
                
                if ($infFiles.Count -eq 0) {
                    return [ValidationResult]::Failure("No .inf driver files found in the specified folder or its subdirectories")
                }
                
                # Validate at least one INF file is accessible
                $accessibleCount = 0
                foreach ($infFile in ($infFiles | Select-Object -First 5)) {
                    try {
                        # Test file accessibility by attempting to read it (content not needed)
                        [System.IO.File]::ReadAllText($infFile.FullName, [System.Text.Encoding]::UTF8) | Out-Null
                        $accessibleCount++
                    }
                    catch {
                        Write-Verbose "INF file not accessible: $($infFile.FullName)"
                    }
                }
                
                if ($accessibleCount -eq 0) {
                    return [ValidationResult]::Failure("Found .inf files but none are accessible for reading")
                }
                
                # Create successful validation result with metadata
                $result = [ValidationResult]::Success($securePath)
                $result.AddData('InfCount', $infFiles.Count)
                $result.AddData('AccessibleCount', $accessibleCount)
                $result.AddData('HasSubdirectories', ($directoryInfo.GetDirectories().Count -gt 0))
                
                Write-Verbose "Driver folder validation completed: $($infFiles.Count) INF files found"
                return $result
            }
            catch [System.UnauthorizedAccessException] {
                return [ValidationResult]::Failure("Access denied when reading driver folder contents")
            }
            catch [System.IO.IOException] {
                return [ValidationResult]::Failure("I/O error when accessing driver folder")
            }
        }
        catch {
            return [ValidationResult]::Failure("Unexpected error during driver folder validation: $($_.Exception.Message)")
        }
    }
}

<#
.SYNOPSIS
    Validates disk space requirements for WIM processing operations.
    
.DESCRIPTION
    Calculates and verifies sufficient disk space for safe WIM operations:
    - Estimates space needed based on WIM file size
    - Applies safety multiplier for temporary files
    - Validates available space on target drive
    - Provides detailed space calculations
    
.PARAMETER WimFilePath
    Path to the WIM file for size calculation
    
.PARAMETER MountDirectory
    Mount directory path for drive space checking
    
.PARAMETER SafetyMultiplier
    Safety multiplier for space calculation (default: 3x)
    
.OUTPUTS
    ValidationResult with space validation outcome and detailed metrics
#>
function Test-DiskSpaceRequirements {
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$WimFilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountDirectory,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(2, 10)]
        [int]$SafetyMultiplier = 3
    )
    
    process {
        try {
            Write-Verbose "Checking disk space requirements for WIM operation..."
            
            # Step 1: Get WIM file size information
            $wimFileInfo = [System.IO.FileInfo]::new($WimFilePath)
            $wimSize = $wimFileInfo.Length
            $requiredSpace = $wimSize * $SafetyMultiplier
            
            # Step 2: Determine target drive for mount directory
            $mountPath = [System.IO.Path]::GetFullPath($MountDirectory)
            $mountDrive = [System.IO.Path]::GetPathRoot($mountPath)
            $driveLetter = $mountDrive.Substring(0, 1)
            
            # Step 3: Get available disk space with error handling
            try {
                $driveInfo = [System.IO.DriveInfo]::new($driveLetter)
                
                # Verify drive is ready and accessible
                if (-not $driveInfo.IsReady) {
                    return [ValidationResult]::Failure("Drive $driveLetter is not ready or accessible")
                }
                
                $freeSpace = $driveInfo.AvailableFreeSpace
                $totalSpace = $driveInfo.TotalSize
            }
            catch [System.ArgumentException] {
                return [ValidationResult]::Failure("Invalid drive letter '$driveLetter' specified in mount directory path")
            }
            catch [System.IO.DriveNotFoundException] {
                return [ValidationResult]::Failure("Drive $driveLetter not found or not accessible")
            }
            catch {
                return [ValidationResult]::Failure("Unable to get disk space information for drive $driveLetter")
            }
            
            # Step 4: Calculate space metrics
            $freeSpaceGB = [math]::Round($freeSpace / 1GB, 2)
            $requiredSpaceGB = [math]::Round($requiredSpace / 1GB, 2)
            $wimSizeGB = [math]::Round($wimSize / 1GB, 2)
            $totalSpaceGB = [math]::Round($totalSpace / 1GB, 2)
            $usedSpacePercent = [math]::Round((($totalSpace - $freeSpace) / $totalSpace) * 100, 1)
            
            Write-Verbose "Space Analysis - WIM: ${wimSizeGB}GB, Required: ${requiredSpaceGB}GB, Available: ${freeSpaceGB}GB, Drive Usage: ${usedSpacePercent}%"
            
            # Step 5: Validate sufficient space with detailed messaging
            if ($freeSpace -lt $requiredSpace) {
                $shortfallGB = [math]::Round(($requiredSpace - $freeSpace) / 1GB, 2)
                $detailMessage = @"
Insufficient disk space on drive $driveLetter

Current Situation:
- WIM File Size: ${wimSizeGB} GB
- Required Space: ${requiredSpaceGB} GB (${SafetyMultiplier}x safety margin)
- Available Space: ${freeSpaceGB} GB
- Drive Usage: ${usedSpacePercent}% of ${totalSpaceGB} GB

Action Required:
Please free up at least ${shortfallGB} GB of space before proceeding.

The safety margin accounts for:
- Temporary mounted image content
- Driver injection working files
- DISM operation overhead
- System file fragmentation
"@
                return [ValidationResult]::Failure($detailMessage)
            }
            
            # Step 6: Warning for low disk space
            if ($freeSpace -lt ($requiredSpace * 1.5)) {
                Write-Warning "Available disk space is close to the minimum requirement. Consider freeing additional space for optimal performance."
            }
            
            # Step 7: Create successful validation result with comprehensive metadata
            $result = [ValidationResult]::Success($mountDrive)
            $result.AddData('FreeSpaceGB', $freeSpaceGB)
            $result.AddData('RequiredSpaceGB', $requiredSpaceGB)
            $result.AddData('WimSizeGB', $wimSizeGB)
            $result.AddData('TotalSpaceGB', $totalSpaceGB)
            $result.AddData('UsedSpacePercent', $usedSpacePercent)
            $result.AddData('SafetyMargin', $SafetyMultiplier)
            $result.AddData('ShortfallGB', 0)
            
            Write-Verbose "Disk space validation completed successfully"
            return $result
        }
        catch {
            return [ValidationResult]::Failure("Unexpected error during disk space validation: $($_.Exception.Message)")
        }
    }
}

<#
.SYNOPSIS
    Verifies DISM tool availability and functionality.
    
.DESCRIPTION
    Validates that the DISM tool is:
    - Available in the system PATH
    - Located in the expected system directory
    - Accessible with current privileges
    - Responsive to basic commands
    
.OUTPUTS
    Boolean indicating DISM tool availability
#>
function Test-DismToolAvailability {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    process {
        try {
            Write-Verbose "Verifying DISM tool availability and functionality..."
            
            # Step 1: Check if DISM command is available
            try {
                $dismCommand = Get-Command "dism.exe" -ErrorAction Stop
                Write-Verbose "DISM found at: $($dismCommand.Source)"
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                Write-Warning "DISM tool not found in system PATH. Please install Windows ADK or verify Windows installation."
                return $false
            }
            
            # Step 2: Verify DISM is in expected system location for security
            $expectedPath = [System.IO.Path]::Combine($env:SystemRoot, "System32", "dism.exe")
            if ($dismCommand.Source -ne $expectedPath) {
                Write-Warning "DISM found at unexpected location: $($dismCommand.Source). Expected: $expectedPath"
                Write-Warning "This may indicate a modified or non-standard installation."
            }
            
            # Step 3: Test DISM basic functionality with a safe command
            try {
                $tempOut = [System.IO.Path]::GetTempFileName()
                $tempErr = [System.IO.Path]::GetTempFileName()
                try {
                    $testProcess = Start-Process -FilePath "dism.exe" -ArgumentList "/?" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
                
                    if ($testProcess.ExitCode -eq 0) {
                        Write-Verbose "DISM tool responded successfully to help command"
                        return $true
                    }
                    else {
                        Write-Warning "DISM tool returned error code: $($testProcess.ExitCode)"
                        return $false
                    }
                }
                finally {
                    Remove-Item -LiteralPath $tempOut -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $tempErr -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Warning "Failed to execute DISM test command: $($_.Exception.Message)"
                return $false
            }
        }
        catch {
            Write-Warning "Unexpected error during DISM availability check: $($_.Exception.Message)"
            return $false
        }
    }
}

<#
.SYNOPSIS
    Sanitizes output text by removing sensitive information patterns.
    
.DESCRIPTION
    Protects against information disclosure by:
    - Removing password-like patterns
    - Masking authentication tokens
    - Sanitizing key/secret references
    - Preserving functional information while enhancing security
    
.PARAMETER OutputText
    Text to sanitize for sensitive information
    
.OUTPUTS
    Sanitized text with sensitive patterns masked
#>
function Protect-SensitiveOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$OutputText
    )
    
    process {
        if ([string]::IsNullOrEmpty($OutputText)) {
            return $OutputText
        }
        
        $sanitizedText = $OutputText
        
        # Apply pre-compiled regex patterns for performance and security
        foreach ($pattern in $script:SensitiveDataPatterns) {
            $sanitizedText = $pattern.Replace($sanitizedText, '***REDACTED***')
        }
        
        return $sanitizedText
    }
}

Write-Verbose "Enhanced security and validation functions loaded successfully"
#endregion

#region 7. Enhanced DISM Operations Module
<#
.SYNOPSIS
    Complete Enhanced Secure DISM command execution with driver management capabilities.
    
.DESCRIPTION
    This region provides secure wrappers for all DISM operations including:
    - Driver inventory and information retrieval
    - Driver removal operations with safety checks
    - Enhanced error handling and validation
    - Comprehensive logging and monitoring
#>

<#
.SYNOPSIS
    Enhanced secure DISM command execution with comprehensive error handling and output parsing.
    
.DESCRIPTION
    Executes DISM commands with advanced security features:
    - Secure argument construction and validation
    - Process isolation and timeout handling
    - Structured output capture and parsing
    - Enhanced error reporting and recovery
    
.PARAMETER Operation
    The DISM operation to execute (e.g., "/Get-Drivers", "/Remove-Driver")
    
.PARAMETER Arguments
    Hashtable of arguments to pass to DISM
    
.PARAMETER TimeoutMs
    Timeout in milliseconds for the operation (default: 5 minutes)
    
.OUTPUTS
    Hashtable with Success, ExitCode, StandardOutput, StandardError, and Duration
#>
function Invoke-EnhancedDismOperation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Operation,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Arguments = @{},
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(10000, 1800000)]
        [int]$TimeoutMs = 300000
    )
    
    begin {
        $startTime = [DateTime]::Now
    }
    
    process {
        try {
            Write-Verbose "Enhanced DISM operation: $Operation"
            
            # Build argument list with proper formatting
            $argumentList = [System.Collections.Generic.List[string]]::new()
            $argumentList.Add($Operation)
            
            # Process arguments with correct formatting
            foreach ($key in $Arguments.Keys) {
                $value = $Arguments[$key]
                
                switch ($key) {
                    'ImageFile' { 
                        $argumentList.Add("/ImageFile:`"$value`"")
                    }
                    'WimFile' { 
                        $argumentList.Add("/WimFile:`"$value`"")
                    }
                    'Image' { 
                        $argumentList.Add("/Image:`"$value`"")
                    }
                    'MountDir' { 
                        $argumentList.Add("/MountDir:`"$value`"")
                    }
                    'Index' { 
                        $argumentList.Add("/Index:$value")
                    }
                    'Driver' { 
                        if ($value -is [array]) {
                            foreach ($driver in $value) {
                                $argumentList.Add("/Driver:`"$driver`"")
                            }
                        }
                        else {
                            $argumentList.Add("/Driver:`"$value`"")
                        }
                    }
                    'Destination' { 
                        $argumentList.Add("/Destination:`"$value`"")
                    }
                    'Recurse' { 
                        if ([bool]$value) { $argumentList.Add("/Recurse") }
                    }
                    'ForceUnsigned' { 
                        if ([bool]$value) { $argumentList.Add("/ForceUnsigned") }
                    }
                    'All' { 
                        if ([bool]$value) { $argumentList.Add("/All") }
                    }
                    'Format' { 
                        $argumentList.Add("/Format:$value")
                    }
                    'Commit' {
                        if ([bool]$value) { $argumentList.Add("/Commit") }
                    }
                    'Discard' {
                        if ([bool]$value) { $argumentList.Add("/Discard") }
                    }
                    default {
                        Write-Verbose "Unknown argument: $key with value: $value"
                    }
                }
            }
            
            # Execute with simplified process management
            $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $processInfo.FileName = "dism.exe"
            $processInfo.Arguments = $argumentList -join ' '
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            
            Write-Verbose "Executing: dism.exe $($processInfo.Arguments)"
            
            $process = [System.Diagnostics.Process]::Start($processInfo)
            $script:ApplicationState.SetCurrentProcess($process)
            
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()

            # Wait for completion with timeout
            $completed = $process.WaitForExit($TimeoutMs)
            $endTime = [DateTime]::Now
            $duration = $endTime - $startTime
            
            if (-not $completed) {
                Write-Warning "DISM operation timed out after $($TimeoutMs / 1000) seconds"
                try {
                    $process.Kill()
                    $process.WaitForExit(5000)
                }
                catch {
                    Write-Warning "Failed to kill timed out DISM process: $($_.Exception.Message)"
                }
                
                return @{
                    Success        = $false
                    ExitCode       = -1
                    StandardOutput = ""
                    StandardError  = "Operation timed out after $($TimeoutMs / 1000) seconds"
                    Duration       = $duration
                    TimedOut       = $true
                }
            }
            
            # Capture output from async tasks
            $standardOutput = $stdoutTask.Result
            $standardError = $stderrTask.Result
            $exitCode = $process.ExitCode
            
            # Clean up
            $process.Dispose()
            $script:ApplicationState.SetCurrentProcess($null)
            
            # Determine success
            $success = ($exitCode -eq 0)
            
            if ($success) {
                Write-Verbose "DISM operation completed successfully in $($duration.TotalSeconds) seconds"
            }
            else {
                Write-Warning "DISM operation failed with exit code: $exitCode"
                if (-not [string]::IsNullOrWhiteSpace($standardError)) {
                    Write-Warning "DISM Error: $($standardError.Substring(0, [Math]::Min($standardError.Length, 250)))"
                }
            }
            
            return @{
                Success        = $success
                ExitCode       = $exitCode
                StandardOutput = $standardOutput
                StandardError  = $standardError
                Duration       = $duration
                TimedOut       = $false
            }
        }
        catch {
            $endTime = [DateTime]::Now
            $duration = $endTime - $startTime
            
            Write-Error "Enhanced DISM operation failed: $($_.Exception.Message)"
            
            return @{
                Success        = $false
                ExitCode       = -2
                StandardOutput = ""
                StandardError  = "Exception: $($_.Exception.Message)"
                Duration       = $duration
                TimedOut       = $false
            }
        }
    }
}

<#
.SYNOPSIS
    Retrieves comprehensive driver inventory from a mounted WIM image.
    
.DESCRIPTION
    Uses DISM to inventory all drivers in a mounted WIM image:
    - Lists both third-party and inbox drivers
    - Parses detailed driver information
    - Determines removal eligibility
    - Provides structured driver objects
    
.PARAMETER MountPath
    Path to the mounted WIM image
    
.PARAMETER IncludeInboxDrivers
    Whether to include Windows inbox drivers (default: true)
    
.OUTPUTS
    Array of InstalledDriverInfo objects representing drivers in the mounted image
#>
function Get-InstalledDriverInventory {
    [CmdletBinding()]
    [OutputType([InstalledDriverInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$MountPath,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeInboxDrivers = $true
    )
    
    process {
        try {
            Write-Verbose "Starting comprehensive driver inventory for: $MountPath"
            Write-ApplicationLog "Retrieving installed driver inventory..." ([LogLevel]::Info)
            
            # Step 1: Get basic driver list
            $arguments = @{
                Image = $MountPath
            }
            
            if ($IncludeInboxDrivers) {
                $arguments.All = $true
                $arguments.Format = "Table"
            }
            
            $result = Invoke-EnhancedDismOperation -Operation $script:Configuration.DismGetDrivers -Arguments $arguments -TimeoutMs $script:Configuration.DriverInventoryTimeoutMs
            
            if (-not $result.Success) {
                Write-ApplicationLog "Failed to retrieve driver inventory: $($result.StandardError)" ([LogLevel]::Error)
                throw "Driver inventory failed: $($result.StandardError)"
            }
            
            # Step 2: Parse driver list output
            $drivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
            $output = $result.StandardOutput
            
            if ([string]::IsNullOrWhiteSpace($output)) {
                Write-ApplicationLog "No driver output received from DISM" ([LogLevel]::Warning)
                return @()
            }
            
            # Step 3: Enhanced parsing for different output formats
            if ($output -match "Published Name") {
                # Table format parsing
                $drivers = ConvertFrom-DriverTableOutput -Output $output
            }
            else {
                # List format parsing (fallback)
                $drivers = ConvertFrom-DriverListOutput -Output $output
            }
            
            # Step 4: Get detailed information for each driver
            $enrichedDrivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
            
            foreach ($driver in $drivers) {
                try {
                    $detailedDriver = Get-DetailedDriverInfo -MountPath $MountPath -PublishedName $driver.PublishedName
                    if ($detailedDriver) {
                        $enrichedDrivers.Add($detailedDriver)
                    }
                }
                catch {
                    Write-Verbose "Could not get detailed info for driver: $($driver.PublishedName)"
                    $enrichedDrivers.Add($driver)
                }
            }
            
            Write-ApplicationLog "Driver inventory completed: $($enrichedDrivers.Count) drivers found" ([LogLevel]::Success)
            return $enrichedDrivers.ToArray()
        }
        catch {
            Write-ApplicationLog "Error during driver inventory: $($_.Exception.Message)" ([LogLevel]::Error)
            throw
        }
    }
}

<#
.SYNOPSIS
    Parses DISM table-formatted driver output into structured objects.
    
.PARAMETER Output
    Raw DISM output text in table format
    
.OUTPUTS
    List of InstalledDriverInfo objects
#>
function ConvertFrom-DriverTableOutput {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[InstalledDriverInfo]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )
    
    process {
        $drivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        
        try {
            # Split into lines and find the header
            $lines = $Output -split "`n" | ForEach-Object { $_.Trim() }
            $headerIndex = -1
            
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match "Published Name.*Original File Name.*Class Name") {
                    $headerIndex = $i
                    break
                }
            }
            
            if ($headerIndex -eq -1) {
                Write-Verbose "Could not find table header in DISM output"
                return $drivers
            }
            
            # Parse data rows
            for ($i = $headerIndex + 2; $i -lt $lines.Count; $i++) {
                $line = $lines[$i].Trim()
                
                if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("-")) {
                    continue
                }
                
                # Parse table columns (space-separated with potential spaces in values)
                if ($line -match "^(oem\d+\.inf|\S+)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(Yes|No)$") {
                    $properties = @{
                        PublishedName    = $matches[1].Trim()
                        OriginalFileName = $matches[2].Trim()
                        ClassName        = $matches[3].Trim()
                        ProviderName     = $matches[4].Trim()
                        DriverDate       = $matches[5].Trim()
                        DriverVersion    = $matches[6].Trim()
                        InboxDriver      = ($matches[7].Trim() -eq "Yes")
                    }
                    
                    $driver = [InstalledDriverInfo]::new($properties)
                    $drivers.Add($driver)
                }
            }
            
            Write-Verbose "Parsed $($drivers.Count) drivers from table output"
            return $drivers
        }
        catch {
            Write-Warning "Error parsing driver table output: $($_.Exception.Message)"
            return [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        }
    }
}

<#
.SYNOPSIS
    Parses DISM list-formatted driver output into structured objects.
    
.PARAMETER Output
    Raw DISM output text in list format
    
.OUTPUTS
    List of InstalledDriverInfo objects
#>
function ConvertFrom-DriverListOutput {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[InstalledDriverInfo]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )
    
    process {
        $drivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        
        try {
            # Parse DISM output which comes in blocks separated by blank lines
            $lines = $Output -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            
            $currentDriver = $null
            foreach ($line in $lines) {
                # Check for start of new driver entry
                if ($line -match "Published Name\s*:\s*(.+)") {
                    # Save previous driver if exists
                    if ($currentDriver) {
                        $driver = [InstalledDriverInfo]::new($currentDriver)
                        $drivers.Add($driver)
                    }
                    
                    # Start new driver
                    $currentDriver = @{
                        PublishedName = $matches[1].Trim()
                        OriginalFileName = "Unknown"
                        ClassName = "Unknown"
                        ProviderName = "Unknown"
                        DriverDate = "Unknown"
                        DriverVersion = "Unknown"
                        InboxDriver = $false
                    }
                }
                elseif ($currentDriver) {
                    # Parse driver properties
                    if ($line -match "Original File Name\s*:\s*(.+)") {
                        $currentDriver.OriginalFileName = $matches[1].Trim()
                    }
                    elseif ($line -match "Class Name\s*:\s*(.+)") {
                        $currentDriver.ClassName = $matches[1].Trim()
                    }
                    elseif ($line -match "Class GUID\s*:\s*(.+)") {
                        $currentDriver.ClassGuid = $matches[1].Trim()
                    }
                    elseif ($line -match "Provider Name\s*:\s*(.+)") {
                        $currentDriver.ProviderName = $matches[1].Trim()
                    }
                    elseif ($line -match "Date\s*:\s*(.+)") {
                        $currentDriver.DriverDate = $matches[1].Trim()
                    }
                    elseif ($line -match "Version\s*:\s*(.+)") {
                        $currentDriver.DriverVersion = $matches[1].Trim()
                    }
                    elseif ($line -match "Inbox\s*:\s*(Yes|No)") {
                        $currentDriver.InboxDriver = ($matches[1].Trim() -eq "Yes")
                    }
                    elseif ($line -match "Boot Critical\s*:\s*(Yes|No)") {
                        $currentDriver.IsBootCritical = ($matches[1].Trim() -eq "Yes")
                    }
                    elseif ($line -match "Architecture\s*:\s*(.+)") {
                        $currentDriver.Architecture = $matches[1].Trim()
                    }
                }
            }
            
            # Add the last driver if exists
            if ($currentDriver) {
                $driver = [InstalledDriverInfo]::new($currentDriver)
                $drivers.Add($driver)
            }
            
            Write-Verbose "Parsed $($drivers.Count) drivers from DISM output"
            return $drivers
        }
        catch {
            Write-Warning "Error parsing driver list output: $($_.Exception.Message)"
            return [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        }
    }
}

<#
.SYNOPSIS
    Retrieves detailed information for a specific installed driver.
    
.PARAMETER MountPath
    Path to the mounted WIM image
    
.PARAMETER PublishedName
    Published name of the driver (e.g., oem1.inf)
    
.OUTPUTS
    Enhanced InstalledDriverInfo object with detailed information
#>
function Get-DetailedDriverInfo {
    [CmdletBinding()]
    [OutputType([InstalledDriverInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MountPath,
        
        [Parameter(Mandatory = $true)]
        [string]$PublishedName
    )
    
    process {
        try {
            Write-Verbose "Getting detailed info for driver: $PublishedName"
            
            $arguments = @{
                Image  = $MountPath
                Driver = $PublishedName
            }
            
            $result = Invoke-EnhancedDismOperation -Operation $script:Configuration.DismGetDriverInfo -Arguments $arguments -TimeoutMs 60000
            
            if (-not $result.Success) {
                Write-Verbose "Could not get detailed info for $PublishedName : $($result.StandardError)"
                return $null
            }
            
            # Parse detailed output
            $output = $result.StandardOutput
            $properties = @{ PublishedName = $PublishedName }
            
            # Extract detailed properties
            foreach ($patternName in $script:DriverOutputPatterns.Keys) {
                $pattern = $script:DriverOutputPatterns[$patternName]
                if ($output -match $pattern) {
                    $properties[$patternName] = $matches[1].Trim()
                }
            }
            
            # Try to extract additional information
            if ($output -match "Architecture\s*:\s*(.+)") {
                $properties.Architecture = $matches[1].Trim()
            }
            
            if ($output -match "Class GUID\s*:\s*(.+)") {
                $properties.ClassGuid = $matches[1].Trim()
            }
            
            return [InstalledDriverInfo]::new($properties)
        }
        catch {
            Write-Verbose "Error getting detailed driver info: $($_.Exception.Message)"
            return $null
        }
    }
}

<#
.SYNOPSIS
    Removes selected drivers from a mounted WIM image with comprehensive safety checks.
    
.DESCRIPTION
    Safely removes drivers from mounted WIM images:
    - Validates removal eligibility for each driver
    - Performs batch removal operations for efficiency
    - Provides detailed progress reporting
    - Implements comprehensive error handling
    
.PARAMETER MountPath
    Path to the mounted WIM image
    
.PARAMETER DriversToRemove
    Array of InstalledDriverInfo objects to remove
    
.PARAMETER Force
    Bypass some safety checks (use with caution)
    
.OUTPUTS
    Hashtable with removal results and detailed statistics
#>
function Remove-DriversFromMountedImage {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$MountPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [InstalledDriverInfo[]]$DriversToRemove,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    begin {
        $startTime = [DateTime]::Now
        $results = @{
            Success            = $false
            TotalDrivers       = $DriversToRemove.Count
            ProcessedDrivers   = 0
            SuccessfulRemovals = 0
            FailedRemovals     = 0
            SkippedDrivers     = 0
            RemovedDriverNames = [System.Collections.Generic.List[string]]::new()
            FailedDriverNames  = [System.Collections.Generic.List[string]]::new()
            SkippedDriverNames = [System.Collections.Generic.List[string]]::new()
            ErrorMessages      = [System.Collections.Generic.List[string]]::new()
            Duration           = [timespan]::Zero
        }
    }
    
    process {
        try {
            Write-ApplicationLog "Starting driver removal operation for $($DriversToRemove.Count) drivers" ([LogLevel]::Info)
            
            if ($DriversToRemove.Count -eq 0) {
                $results.Success = $true
                $results.Duration = [DateTime]::Now - $startTime
                return $results
            }
            
            # Step 1: Validate and filter drivers for removal
            $eligibleDrivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
            
            foreach ($driver in $DriversToRemove) {
                $results.ProcessedDrivers++
                
                # Safety checks
                if (-not $Force -and (-not $driver.CanBeRemoved -or $driver.IsBootCritical -or $driver.IsInboxDriver)) {
                    Write-Verbose "Skipping protected driver: $($driver.PublishedName) - $($driver.GetRemovalStatusText())"
                    $results.SkippedDrivers++
                    $results.SkippedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                    continue
                }
                
                # Additional safety check for protected classes
                if (-not $Force -and $driver.ClassName -in $script:Configuration.ProtectedDriverClasses) {
                    Write-Verbose "Skipping driver in protected class: $($driver.PublishedName) - $($driver.ClassName)"
                    $results.SkippedDrivers++
                    $results.SkippedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                    continue
                }
                
                $eligibleDrivers.Add($driver)
            }
            
            Write-ApplicationLog "Driver removal validation: $($eligibleDrivers.Count) eligible, $($results.SkippedDrivers) skipped" ([LogLevel]::Info)
            
            if ($eligibleDrivers.Count -eq 0) {
                Write-ApplicationLog "No drivers eligible for removal after safety validation" ([LogLevel]::Warning)
                $results.Success = $true
                $results.Duration = [DateTime]::Now - $startTime
                return $results
            }
            
            # Step 2: Batch removal for efficiency (but limit batch size for safety)
            $batchSize = [Math]::Min($eligibleDrivers.Count, $script:Configuration.MaxDriversForRemoval)
            $totalBatches = [Math]::Ceiling($eligibleDrivers.Count / $batchSize)
            
            for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
                $startIndex = $batchIndex * $batchSize
                $endIndex = [Math]::Min($startIndex + $batchSize - 1, $eligibleDrivers.Count - 1)
                $batchDrivers = $eligibleDrivers[$startIndex..$endIndex]
                
                Write-ApplicationLog "Processing removal batch $($batchIndex + 1)/$totalBatches ($($batchDrivers.Count) drivers)" ([LogLevel]::Info)
                
                # Step 3: Execute batch removal
                $driverNames = $batchDrivers | ForEach-Object { $_.PublishedName }
                
                $arguments = @{
                    Image  = $MountPath
                    Driver = $driverNames
                }
                
                $batchResult = Invoke-EnhancedDismOperation -Operation $script:Configuration.DismRemoveDriver -Arguments $arguments -TimeoutMs $script:Configuration.DriverRemovalTimeoutMs
                
                if ($batchResult.Success) {
                    # All drivers in batch succeeded
                    $results.SuccessfulRemovals += $batchDrivers.Count
                    foreach ($driver in $batchDrivers) {
                        $results.RemovedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                        Write-Verbose "Successfully removed driver: $($driver.PublishedName)"
                    }
                    Write-ApplicationLog "Batch $($batchIndex + 1) completed successfully: $($batchDrivers.Count) drivers removed" ([LogLevel]::Success)
                }
                else {
                    # Batch failed - try individual removal for better error reporting
                    Write-ApplicationLog "Batch $($batchIndex + 1) failed, attempting individual removal" ([LogLevel]::Warning)
                    
                    foreach ($driver in $batchDrivers) {
                        try {
                            $individualArgs = @{
                                Image  = $MountPath
                                Driver = $driver.PublishedName
                            }
                            
                            $individualResult = Invoke-EnhancedDismOperation -Operation $script:Configuration.DismRemoveDriver -Arguments $individualArgs -TimeoutMs 60000
                            
                            if ($individualResult.Success) {
                                $results.SuccessfulRemovals++
                                $results.RemovedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                                Write-Verbose "Successfully removed driver: $($driver.PublishedName)"
                            }
                            else {
                                $results.FailedRemovals++
                                $results.FailedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                                $results.ErrorMessages.Add("$($driver.PublishedName): $($individualResult.StandardError)")
                                Write-Verbose "Failed to remove driver: $($driver.PublishedName) - $($individualResult.StandardError)"
                            }
                        }
                        catch {
                            $results.FailedRemovals++
                            $results.FailedDriverNames.Add("$($driver.PublishedName) ($($driver.ClassName))")
                            $results.ErrorMessages.Add("$($driver.PublishedName): $($_.Exception.Message)")
                            Write-Verbose "Exception removing driver: $($driver.PublishedName) - $($_.Exception.Message)"
                        }
                    }
                }
                
                # Update progress
                $progressPercent = (($batchIndex + 1) / $totalBatches) * 100
                Update-ApplicationProgress $progressPercent "Removing drivers: batch $($batchIndex + 1)/$totalBatches"
            }
            
            # Step 4: Final results compilation
            $results.Success = ($results.SuccessfulRemovals -gt 0) -and ($results.FailedRemovals -eq 0)
            $results.Duration = [DateTime]::Now - $startTime
            
            # Step 5: Comprehensive logging
            $summary = @"
Driver Removal Operation Summary:
- Total Processed: $($results.ProcessedDrivers)
- Successfully Removed: $($results.SuccessfulRemovals)
- Failed Removals: $($results.FailedRemovals)
- Skipped (Protected): $($results.SkippedDrivers)
- Duration: $($results.Duration.ToString("mm\:ss"))
"@
            
            if ($results.Success) {
                Write-ApplicationLog $summary ([LogLevel]::Success)
            }
            else {
                Write-ApplicationLog $summary ([LogLevel]::Warning)
            }
            
            return $results
        }
        catch {
            $results.Duration = [DateTime]::Now - $startTime
            $results.ErrorMessages.Add("Critical error: $($_.Exception.Message)")
            Write-ApplicationLog "Critical error during driver removal: $($_.Exception.Message)" ([LogLevel]::Error)
            return $results
        }
    }
}

<#
.SYNOPSIS
    Exports selected drivers from a mounted WIM image for backup purposes.
    
.PARAMETER MountPath
    Path to the mounted WIM image
    
.PARAMETER DestinationPath
    Directory where drivers will be exported
    
.PARAMETER DriversToExport
    Optional array of specific drivers to export (if empty, exports all third-party drivers)
    
.OUTPUTS
    Hashtable with export results
#>
function Export-DriversFromMountedImage {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$MountPath,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $false)]
        [InstalledDriverInfo[]]$DriversToExport = @()
    )
    
    process {
        try {
            Write-ApplicationLog "Starting driver export operation to: $DestinationPath" ([LogLevel]::Info)
            
            # Create destination directory if it doesn't exist
            if (-not [System.IO.Directory]::Exists($DestinationPath)) {
                [System.IO.Directory]::CreateDirectory($DestinationPath) | Out-Null
            }
            
            $arguments = @{
                Image       = $MountPath
                Destination = $DestinationPath
            }
            
            $result = Invoke-EnhancedDismOperation -Operation $script:Configuration.DismExportDriver -Arguments $arguments -TimeoutMs 300000
            
            if ($result.Success) {
                Write-ApplicationLog "Driver export completed successfully" ([LogLevel]::Success)
                return @{
                    Success         = $true
                    DestinationPath = $DestinationPath
                    Message         = "Drivers exported successfully"
                }
            }
            else {
                Write-ApplicationLog "Driver export failed: $($result.StandardError)" ([LogLevel]::Error)
                return @{
                    Success      = $false
                    ErrorMessage = $result.StandardError
                    Message      = "Driver export failed"
                }
            }
        }
        catch {
            Write-ApplicationLog "Error during driver export: $($_.Exception.Message)" ([LogLevel]::Error)
            return @{
                Success      = $false
                ErrorMessage = $_.Exception.Message
                Message      = "Driver export failed with exception"
            }
        }
    }
}

<#
.SYNOPSIS
    Recursively discovers driver files from a directory path with enhanced filtering.
    
.PARAMETER RootPath
    Root directory to search for driver files
    
.OUTPUTS
    Array of DriverInfo objects for discovered drivers
#>
function Get-DriversRecursive {
    [CmdletBinding()]
    [OutputType([DriverInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$RootPath
    )
    
    process {
        try {
            Write-Verbose "Starting enhanced recursive driver discovery in: $RootPath"
            
            $drivers = [System.Collections.Generic.List[DriverInfo]]::new()
            $pathValidation = Test-SecurePath -Path $RootPath
            
            if (-not $pathValidation.IsValid) {
                Write-Warning "Path security validation failed: $($pathValidation.ErrorMessage)"
                return @()
            }
            
            $securePath = $pathValidation.ResolvedPath
            $discoveredFiles = [System.IO.Directory]::GetFiles($securePath, "*.inf", [System.IO.SearchOption]::AllDirectories)
            
            Write-Verbose "Found $($discoveredFiles.Count) INF files for processing"
            
            $processedCount = 0
            foreach ($infFile in $discoveredFiles) {
                try {
                    $driver = [DriverInfo]::new($infFile)
                    $drivers.Add($driver)
                    $processedCount++
                    
                    if ($processedCount % 10 -eq 0) {
                        Write-Verbose "Processed $processedCount/$($discoveredFiles.Count) driver files"
                    }
                }
                catch {
                    Write-Warning "Failed to process driver file: $infFile - $($_.Exception.Message)"
                }
            }
            
            Write-Verbose "Enhanced driver discovery completed: $($drivers.Count) valid drivers found"
            return $drivers.ToArray()
        }
        catch {
            Write-Error "Enhanced recursive driver discovery failed: $($_.Exception.Message)"
            return @()
        }
    }
}

<#
.SYNOPSIS
    Retrieves all available indexes from a WIM file using enhanced DISM operations.
    
.PARAMETER WimFilePath
    Path to the WIM file to analyze
    
.OUTPUTS
    Array of integers representing available WIM indexes
#>
function Get-WimIndexes {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$WimFilePath
    )
    
    process {
        try {
            Write-Verbose "Reading WIM indexes from: $WimFilePath"
            Write-ApplicationLog "Scanning WIM file for available indexes..." ([LogLevel]::Info)
            
            # Get the full path to ensure it's absolute
            $fullWimPath = [System.IO.Path]::GetFullPath($WimFilePath)
            Write-Verbose "Full WIM path: $fullWimPath"
            
            # Use enhanced DISM operation with proper argument structure
            $arguments = @{
                WimFile = $fullWimPath
            }
            
            Write-Verbose "Executing enhanced DISM Get-WimInfo operation"
            $result = Invoke-EnhancedDismOperation -Operation "/Get-WimInfo" -Arguments $arguments -TimeoutMs 60000
            
            if ($result.Success) {
                Write-Verbose "DISM Get-WimInfo completed successfully"
                
                # Parse index information from DISM output
                $indexMatches = [regex]::Matches($result.StandardOutput, "Index\s*:\s*(\d+)")
                $indexes = [System.Collections.Generic.List[int]]::new()
                
                Write-Verbose "Found $($indexMatches.Count) index matches in DISM output"
                
                foreach ($match in $indexMatches) {
                    $indexNumber = [int]$match.Groups[1].Value
                    if ($indexNumber -gt 0) {
                        $indexes.Add($indexNumber)
                        Write-Verbose "Added index: $indexNumber"
                    }
                }
                
                if ($indexes.Count -eq 0) {
                    Write-Verbose "No valid indexes found - checking for alternative formats"
                    Write-ApplicationLog "No valid indexes found in WIM file" ([LogLevel]::Warning)
                    throw "No valid indexes found in WIM file. The file may be corrupted or empty."
                }
                
                # Sort indexes for consistent processing order
                $sortedIndexes = $indexes.ToArray() | Sort-Object
                Write-ApplicationLog "Found $($sortedIndexes.Count) valid indexes: $($sortedIndexes -join ', ')" ([LogLevel]::Success)
                return $sortedIndexes
            }
            else {
                $errorMessage = "Failed to read WIM file information. Exit code: $($result.ExitCode)"
                if (-not [string]::IsNullOrWhiteSpace($result.StandardError)) {
                    $errorMessage += ". Error: $($result.StandardError)"
                }
                Write-ApplicationLog $errorMessage ([LogLevel]::Error)
                throw $errorMessage
            }
        }
        catch {
            Write-Error "Cannot read WIM file indexes: $($_.Exception.Message)"
            Write-ApplicationLog "Error reading WIM indexes: $($_.Exception.Message)" ([LogLevel]::Error)
            throw
        }
    }
}

#region Driver Target Suitability Classification
<#
.SYNOPSIS
    Determines whether a WIM file is a boot image (boot.wim / Windows PE) or a
    full installation image (install.wim), so driver injection can be targeted.

.DESCRIPTION
    Detection order:
    1. Filename heuristic (boot.wim, boot.esd, winre.wim -> Boot; install.wim/esd -> Install).
    2. Content fallback via DISM /Get-WimInfo index names
       ("Windows PE" / "Windows Setup" -> Boot; edition names -> Install).

.PARAMETER WimFilePath
    Path to the WIM/ESD file to classify.

.OUTPUTS
    WimImageType enum value (Boot, Install, or Unknown).
#>
function Get-WimImageType {
    [CmdletBinding()]
    [OutputType([WimImageType])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WimFilePath
    )

    process {
        try {
            $fileName = [System.IO.Path]::GetFileName($WimFilePath).ToLowerInvariant()
            if (($fileName -eq 'boot.wim') -or ($fileName -eq 'boot.esd') -or ($fileName -eq 'winre.wim')) {
                return [WimImageType]::Boot
            }
            if (($fileName -eq 'install.wim') -or ($fileName -eq 'install.esd')) {
                return [WimImageType]::Install
            }

            $fullWimPath = [System.IO.Path]::GetFullPath($WimFilePath)
            $result = Invoke-EnhancedDismOperation -Operation '/Get-WimInfo' -Arguments @{ WimFile = $fullWimPath } -TimeoutMs 60000
            if ($result.Success) {
                $output = $result.StandardOutput
                if (($output -match 'Windows PE') -or ($output -match 'Windows Setup')) {
                    return [WimImageType]::Boot
                }
                if ($output -match 'Windows\s+(10|11|Server).*(Pro|Home|Enterprise|Education|Standard|Datacenter|Core|IoT)') {
                    return [WimImageType]::Install
                }
            }
            return [WimImageType]::Unknown
        }
        catch {
            Write-Verbose "Could not determine WIM image type: $($_.Exception.Message)"
            return [WimImageType]::Unknown
        }
    }
}

<#
.SYNOPSIS
    Determines the CPU architecture of a WIM image from DISM index names.

.PARAMETER WimFilePath
    Path to the WIM/ESD file to inspect.

.OUTPUTS
    String architecture: X64, ARM64, X86, or Unknown.
#>
function Get-WimArchitecture {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WimFilePath
    )

    process {
        try {
            $fullWimPath = [System.IO.Path]::GetFullPath($WimFilePath)
            # First pass: index names may carry the architecture (e.g. boot.wim
            # reports "Microsoft Windows PE (x64)").
            $result = Invoke-EnhancedDismOperation -Operation '/Get-WimInfo' -Arguments @{ WimFile = $fullWimPath } -TimeoutMs 60000
            if ($result.Success) {
                $output = $result.StandardOutput
                if ($output -match 'ARM64') { return 'ARM64' }
                if ($output -match '\(x64\)|AMD64') { return 'X64' }
                if ($output -match '\(x86\)') { return 'X86' }
            }
            # Fallback: install.wim index names often omit the architecture, but
            # the detailed single-index view exposes an 'Architecture :' field.
            $detail = Invoke-EnhancedDismOperation -Operation '/Get-WimInfo' -Arguments @{ WimFile = $fullWimPath; Index = 1 } -TimeoutMs 60000
            if ($detail.Success) {
                $detailOutput = $detail.StandardOutput
                if ($detailOutput -match '(?i)Architecture\s*:\s*ARM64') { return 'ARM64' }
                if ($detailOutput -match '(?i)Architecture\s*:\s*(x64|AMD64)') { return 'X64' }
                if ($detailOutput -match '(?i)Architecture\s*:\s*x86') { return 'X86' }
            }
            return 'Unknown'
        }
        catch {
            return 'Unknown'
        }
    }
}

<#
.SYNOPSIS
    Parses the setup Class value from an INF file.

.PARAMETER InfPath
    Path to the INF file.

.OUTPUTS
    Class string (e.g. 'net', 'System', 'MEDIA'), or 'Unknown'.
#>
function Get-InfDriverClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InfPath
    )

    process {
        try {
            if (-not [System.IO.File]::Exists($InfPath)) { return 'Unknown' }
            $lines = [System.IO.File]::ReadAllLines($InfPath)
            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ($trimmed.StartsWith(';')) { continue }
                if ($trimmed -match '^Class\s*=\s*"?([^"\r\n;]+)"?') {
                    $cls = $Matches[1].Trim()
                    if (-not [string]::IsNullOrWhiteSpace($cls)) { return $cls }
                }
            }
            return 'Unknown'
        }
        catch {
            return 'Unknown'
        }
    }
}

<#
.SYNOPSIS
    Determines which CPU architectures an INF driver package supports by reading
    the NT architecture decorations (NTamd64 / NTarm64 / NTx86) used in the
    [Manufacturer] models and decorated sections.

.PARAMETER InfPath
    Path to the INF file.

.OUTPUTS
    String array of supported architectures (X64, ARM64, X86). Empty if none found.
#>
function Get-InfSupportedArchitectures {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InfPath
    )

    process {
        $archs = [System.Collections.Generic.List[string]]::new()
        try {
            if (-not [System.IO.File]::Exists($InfPath)) { return @() }
            $content = [System.IO.File]::ReadAllText($InfPath)
            if ($content -match '(?i)NTamd64') { $archs.Add('X64') }
            if ($content -match '(?i)NTarm64') { $archs.Add('ARM64') }
            if ($content -match '(?i)NTx86') { $archs.Add('X86') }
            return $archs.ToArray()
        }
        catch {
            return @()
        }
    }
}

<#
.SYNOPSIS
    Detects whether an INF describes a storage controller driver. Used to pick
    the storage controllers out of the ambiguous 'System' class so that only the
    drivers Windows PE needs to see the disk are injected into boot.wim.

.DESCRIPTION
    Two precise signals are used, both chosen to avoid false positives from
    chipset/thermal drivers:
    1. A PCI mass-storage class code (CC_01xx) in a hardware ID. This is the
       definitive storage-controller indicator. Chipset, thermal (DPTF), audio
       and other System-class devices use other class codes and never CC_01xx.
    2. A known storage service binary referenced as a .sys file, matched with a
       word boundary. Requiring '.sys' plus a word boundary prevents matches on
       unrelated filenames such as 'upe_nvme.dll' (a thermal component).

.PARAMETER InfPath
    Path to the INF file.

.OUTPUTS
    Boolean: true if the INF is a storage controller driver.
#>
function Test-IsStorageControllerDriver {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InfPath
    )

    process {
        try {
            if (-not [System.IO.File]::Exists($InfPath)) { return $false }
            $content = [System.IO.File]::ReadAllText($InfPath)

            # Primary: PCI mass-storage controller class code (base class 01).
            if ($content -match 'CC_01[0-9A-Fa-f]{2}') { return $true }

            # Secondary: a known storage service binary referenced as a .sys file.
            foreach ($svc in $script:Configuration.StorageServicePatterns) {
                $pattern = '(?i)\b' + [regex]::Escape($svc) + '\w*\.sys'
                if ($content -match $pattern) { return $true }
            }
            return $false
        }
        catch {
            return $false
        }
    }
}

<#
.SYNOPSIS
    Core judgment: decides whether a driver is suitable for injection into a
    specific WIM image type (boot.wim vs install.wim), with a human-readable reason.

.DESCRIPTION
    Rules:
    - Unknown image type -> allow by default (cannot judge).
    - Architecture gate -> if the image architecture is known and the driver does
      not support it, reject with 'Architecture mismatch'.
    - install.wim -> any architecture-matched driver is suitable.
    - boot.wim -> only storage/network allowlist classes, plus 'System' class
      drivers that are storage controllers. Everything else is rejected.

.PARAMETER Driver
    The DriverInfo object to evaluate.

.PARAMETER ImageType
    Target image type (Boot, Install, Unknown).

.PARAMETER ImageArchitecture
    Target image architecture (X64, ARM64, X86, Unknown).

.OUTPUTS
    PSCustomObject with Suitable (bool), Reason (string), Class (string).
#>
function Test-DriverSuitabilityForImage {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [DriverInfo]$Driver,

        [Parameter(Mandatory = $true)]
        [WimImageType]$ImageType,

        [Parameter(Mandatory = $false)]
        [string]$ImageArchitecture = 'Unknown'
    )

    process {
        $result = [PSCustomObject]@{
            Suitable = $true
            Reason   = ''
            Class    = 'Unknown'
        }
        try {
            $infPath = $Driver.FullPath
            $class = Get-InfDriverClass -InfPath $infPath
            $result.Class = $class

            if ($ImageType -eq [WimImageType]::Unknown) {
                $result.Suitable = $true
                $result.Reason = 'Image type unknown - allowed by default'
                return $result
            }

            if (-not [string]::IsNullOrWhiteSpace($ImageArchitecture) -and ($ImageArchitecture -ne 'Unknown')) {
                $supported = @(Get-InfSupportedArchitectures -InfPath $infPath)
                if (($supported.Count -gt 0) -and ($supported -notcontains $ImageArchitecture)) {
                    $supportedText = $supported -join '/'
                    $result.Suitable = $false
                    $result.Reason = "Architecture mismatch (driver: $supportedText, image: $ImageArchitecture)"
                    return $result
                }
            }

            if ($ImageType -eq [WimImageType]::Install) {
                $result.Suitable = $true
                $result.Reason = 'Suitable for install.wim'
                return $result
            }

            if ($ImageType -eq [WimImageType]::Boot) {
                $allowed = $script:Configuration.BootWimAllowedClasses
                $classMatch = @($allowed | Where-Object { $_ -ieq $class })
                if ($classMatch.Count -gt 0) {
                    $result.Suitable = $true
                    $result.Reason = "boot.wim-relevant class: $class"
                    return $result
                }

                if ($class -ieq 'System') {
                    if (Test-IsStorageControllerDriver -InfPath $infPath) {
                        $result.Suitable = $true
                        $result.Reason = 'System-class storage controller (needed for Setup to see the disk)'
                        return $result
                    }
                    $result.Suitable = $false
                    $result.Reason = 'System-class chipset driver (not needed in Windows PE)'
                    return $result
                }

                $result.Suitable = $false
                $result.Reason = "Class '$class' is not needed in Windows PE"
                return $result
            }

            $result.Suitable = $true
            $result.Reason = 'Allowed by default'
            return $result
        }
        catch {
            $result.Suitable = $true
            $result.Reason = "Judgment error: $($_.Exception.Message)"
            return $result
        }
    }
}

Write-Verbose "Driver target suitability classification functions loaded successfully"
#endregion

<#
.SYNOPSIS
    Safely clears and prepares a mount directory for WIM operations.
    
.PARAMETER MountPath
    Path to the mount directory to prepare
    
.OUTPUTS
    Boolean indicating successful directory preparation
#>
function Clear-MountDirectory {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountPath
    )
    
    process {
        try {
            Write-ApplicationLog "Preparing mount directory: $MountPath" ([LogLevel]::Info)
            
            # Step 1: Check if the directory exists
            if ([System.IO.Directory]::Exists($MountPath)) {
                Write-ApplicationLog "Existing mount directory found. Initiating cleanup..." ([LogLevel]::Warning)

                # Step 1a: Attempt targeted unmount first
                Write-Verbose "Attempting targeted unmount on '$MountPath'..."
                try {
                    $unmountArgs = @{ MountDir = $MountPath; Discard = $true }
                    $unmountResult = Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $unmountArgs -TimeoutMs 60000
                    if ($unmountResult.Success) {
                        Write-ApplicationLog "Successfully unmounted existing image from the target directory." ([LogLevel]::Success)
                    } else {
                        # This is expected if it wasn't a valid mount point
                        Write-Verbose "Targeted unmount did not succeed (this is okay if it wasn't a mount point)."
                    }
                }
                catch {
                    Write-Verbose "Exception during targeted unmount (ignoring): $($_.Exception.Message)"
                }

                # Step 1b: Run global DISM cleanup
                Write-Verbose "Running global 'dism.exe /Cleanup-Mountpoints' as a fallback..."
                try {
                    $cleanupProcess = Start-Process "dism.exe" -ArgumentList "/Cleanup-Mountpoints" -Wait -PassThru -NoNewWindow
                    if ($cleanupProcess.ExitCode -eq 0) {
                        Write-ApplicationLog "Global DISM cleanup completed successfully." ([LogLevel]::Info)
                    } else {
                        Write-ApplicationLog "Global DISM cleanup reported exit code: $($cleanupProcess.ExitCode)" ([LogLevel]::Warning)
                    }
                }
                catch {
                    Write-ApplicationLog "Could not run global DISM cleanup: $($_.Exception.Message)" ([LogLevel]::Warning)
                }

                # Step 1c: After DISM cleanup, try Remove-Item
                if ([System.IO.Directory]::Exists($MountPath)) {
                    Write-Verbose "Directory still exists after DISM cleanup. Attempting removal."
                    Start-Sleep -Seconds 2 # Give file handles a moment to release
                    
                    # Check if directory is empty or contains only small temp files
                    $items = Get-ChildItem -Path $MountPath -Force -ErrorAction SilentlyContinue
                    if ($items.Count -gt 0) {
                        Write-Verbose "Directory contains $($items.Count) items"
                        
                        # If directory has Windows folder, it's likely still mounted
                        $windowsPath = Join-Path $MountPath "Windows"
                        if (Test-Path $windowsPath) {
                            Write-ApplicationLog "WARNING: Mount directory appears to contain a mounted image. Forcing unmount..." ([LogLevel]::Warning)
                            
                            # Force unmount with discard
                            try {
                                $forceUnmountArgs = @{ MountDir = $MountPath; Discard = $true }
                                Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $forceUnmountArgs -TimeoutMs 120000 | Out-Null
                                Start-Sleep -Seconds 3
                            }
                            catch {
                                Write-ApplicationLog "Force unmount attempt failed: $($_.Exception.Message)" ([LogLevel]::Warning)
                            }
                        }
                    }
                    
                    try {
                        Remove-Item -Path $MountPath -Recurse -Force -ErrorAction Stop
                        Write-ApplicationLog "Successfully removed mount directory." ([LogLevel]::Info)
                    }
                    catch {
                        # If removal fails, at least try to empty it
                        Write-ApplicationLog "Could not remove directory, attempting to empty it: $($_.Exception.Message)" ([LogLevel]::Warning)
                        try {
                            Get-ChildItem -Path $MountPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Verbose "Could not empty directory: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Step 2: Create a fresh, empty directory for the new mount
            if (-not [System.IO.Directory]::Exists($MountPath)) {
                Write-Verbose "Creating a new mount directory at '$MountPath'."
                [System.IO.Directory]::CreateDirectory($MountPath) | Out-Null
                Write-ApplicationLog "Mount directory created and ready." ([LogLevel]::Success)
            }
            else {
                Write-ApplicationLog "Mount directory exists and is ready." ([LogLevel]::Info)
            }

            return $true
        }
        catch {
            Write-Error "Failed to prepare mount directory: $($_.Exception.Message)"
            Write-ApplicationLog "Failed to prepare mount directory: $($_.Exception.Message)" ([LogLevel]::Error)
            return $false
        }
    }
}

Write-Verbose "Enhanced DISM operations module with driver management loaded successfully"
#endregion

#region 8. Simplified Driver Management Functions
<#
.SYNOPSIS
    Simplified driver discovery and management functions.
    
.DESCRIPTION
    This region provides streamlined driver management:
    - Simplified driver selection from UI
    - Consistent with enhanced DISM operations
    - Reduced complexity while maintaining functionality
#>

<#
.SYNOPSIS
    Gets currently selected drivers from the UI with enhanced error handling.
    
.DESCRIPTION
    Retrieves drivers selected by the user in the driver selection interface:
    - Processes all checkboxes in the driver list
    - Filters for checked items with valid driver objects
    - Provides comprehensive error handling
    - Returns array of selected DriverInfo objects
    
.OUTPUTS
    Array of DriverInfo objects representing selected drivers
#>
function Get-SelectedDrivers {
    try {
        $selectedDrivers = @()
        
        if (-not $script:MainWindow) {
            Write-Warning "Main window reference not available"
            return @()
        }
        
        $driverListPanel = $script:MainWindow.FindName("DriverListPanel")
        if (-not $driverListPanel) {
            Write-Warning "Driver list panel not found in UI"
            return @()
        }
        
        # Get all checkboxes using improved logic
        $checkboxes = @()
        foreach ($child in $driverListPanel.Children) {
            try {
                # Skip header borders (manufacturer group headers)
                if ($child -is [System.Windows.Controls.Border] -and 
                    $child.Child -is [System.Windows.Controls.Grid] -and 
                    $child.Child.Children[1] -is [System.Windows.Controls.TextBlock]) {
                    continue
                }
                
                # Look for driver item containers
                if ($child -is [System.Windows.Controls.Border] -and $child.Child -is [System.Windows.Controls.Grid]) {
                    $grid = $child.Child
                    foreach ($gridChild in $grid.Children) {
                        if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                            $checkboxes += $gridChild
                            break
                        }
                    }
                }
                # Fallback: direct Grid containers
                elseif ($child -is [System.Windows.Controls.Grid]) {
                    foreach ($gridChild in $child.Children) {
                        if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                            $checkboxes += $gridChild
                            break
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error processing UI element: $($_.Exception.Message)"
            }
        }
        
        # Find selected drivers
        foreach ($checkBox in $checkboxes) {
            try {
                if ($checkBox.IsChecked -eq $true -and $checkBox.Tag) {
                    $driver = $checkBox.Tag -as [DriverInfo]
                    if ($driver) {
                        $selectedDrivers += $driver
                    }
                }
            }
            catch {
                Write-Verbose "Error processing checkbox: $($_.Exception.Message)"
            }
        }
        
        Write-Verbose "Retrieved $($selectedDrivers.Count) selected drivers from UI"
        return $selectedDrivers
    }
    catch {
        Write-Warning "Error getting selected drivers: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Validates a driver selection for workflow execution.
    
.DESCRIPTION
    Performs validation checks on selected drivers:
    - Ensures drivers are accessible
    - Checks for mixed signed/unsigned drivers
    - Validates driver file integrity
    - Provides recommendations for processing method
    
.PARAMETER SelectedDrivers
    Array of DriverInfo objects to validate
    
.OUTPUTS
    Hashtable with validation results and recommendations
#>
function Test-DriverSelection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [DriverInfo[]]$SelectedDrivers
    )
    
    process {
        try {
            $result = @{
                IsValid             = $true
                Messages            = @()
                SignedCount         = 0
                UnsignedCount       = 0
                InaccessibleCount   = 0
                RecommendBatchStyle = $false
                TotalSize           = 0
            }
            
            if ($SelectedDrivers.Count -eq 0) {
                $result.IsValid = $false
                $result.Messages += "No drivers selected for injection"
                return $result
            }
            
            # Analyze driver selection
            foreach ($driver in $SelectedDrivers) {
                # Check accessibility
                if (-not [System.IO.File]::Exists($driver.FullPath)) {
                    $result.InaccessibleCount++
                    $result.Messages += "Driver file not accessible: $($driver.Name)"
                    continue
                }
                
                # Count signed/unsigned
                if ($driver.IsSigned()) {
                    $result.SignedCount++
                }
                else {
                    $result.UnsignedCount++
                }
                
                # Calculate total size
                try {
                    $fileInfo = [System.IO.FileInfo]::new($driver.FullPath)
                    $result.TotalSize += $fileInfo.Length
                }
                catch {
                    Write-Verbose "Could not get size for driver: $($driver.Name)"
                }
            }
            
            # Validation checks
            if ($result.InaccessibleCount -gt 0) {
                $result.IsValid = $false
                $result.Messages += "$($result.InaccessibleCount) driver files are not accessible"
            }
            
            # Recommendations
            if ($SelectedDrivers.Count -gt 15) {
                $result.RecommendBatchStyle = $true
                $result.Messages += "Large driver set detected - consider batch-style processing for speed"
            }
            
            if ($result.UnsignedCount -gt 0) {
                $result.Messages += "Warning: $($result.UnsignedCount) unsigned drivers selected"
            }
            
            # Success summary
            if ($result.IsValid) {
                $totalSizeMB = [math]::Round($result.TotalSize / 1MB, 1)
                $result.Messages += "Validation successful: $($SelectedDrivers.Count) drivers, ${totalSizeMB}MB total"
            }
            
            return $result
        }
        catch {
            return @{
                IsValid             = $false
                Messages            = @("Validation error: $($_.Exception.Message)")
                SignedCount         = 0
                UnsignedCount       = 0
                InaccessibleCount   = 0
                RecommendBatchStyle = $false
                TotalSize           = 0
            }
        }
    }
}

Write-Verbose "Simplified driver management functions loaded successfully"
#endregion

#region 9. Enhanced UI Helper Functions with Thread Safety
<#
.SYNOPSIS
    Thread-safe UI update and management functions.
    
.DESCRIPTION
    This region provides safe UI interaction capabilities:
    - Thread-safe logging with output sanitization
    - Progress updates with validation
    - Workflow state management
    - Visual feedback and accessibility support
#>

<#
.SYNOPSIS
    Writes messages to the application log with thread safety and security.
    
.DESCRIPTION
    Provides comprehensive logging functionality:
    - Thread-safe UI updates using Dispatcher
    - Output sanitization for security
    - Timestamp and level formatting
    - Graceful fallback to verbose logging
    
.PARAMETER Message
    The message to log
    
.PARAMETER Level
    The severity level of the message
#>
function Write-ApplicationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [object]$Level = "Info"
    )
    
    process {
        try {
            # Convert level to string if it's an enum
            $levelString = if ($Level -is [string]) { $Level } else { $Level.ToString() }
            
            # Step 1: Create formatted log entry with security sanitization
            $timestamp = Get-Date -Format "HH:mm:ss"
            $sanitizedMessage = if (Get-Command -Name "Protect-SensitiveOutput" -ErrorAction SilentlyContinue) {
                Protect-SensitiveOutput -OutputText $Message
            }
            else {
                $Message
            }
            $logEntry = "[$timestamp] [$levelString] $sanitizedMessage"
            
            # Step 2: UI update with error handling
            if ($script:MainWindow -and $script:MainWindow.Dispatcher -and -not $script:MainWindow.Dispatcher.HasShutdownStarted) {
                try {
                    # Use Invoke instead of BeginInvoke to reduce resource usage
                    $script:MainWindow.Dispatcher.Invoke([System.Action] {
                            try {
                                $logTextBox = $script:MainWindow.FindName("LogTextBox")
                                if ($logTextBox -and $logTextBox.IsLoaded) {
                                    # Limit log text length to prevent memory issues
                                    $currentText = $logTextBox.Text
                                    if ($currentText.Length -gt 50000) {
                                        # Keep only the last 30000 characters
                                        $logTextBox.Text = $currentText.Substring($currentText.Length - 30000)
                                    }
                                
                                    # Append new entry
                                    $logTextBox.AppendText("$logEntry`n")
                                    $logTextBox.ScrollToEnd()
                                }
                            }
                            catch {
                                # Silent failure in UI thread to prevent cascade errors
                                Write-Verbose "UI log update failed: $($_.Exception.Message)"
                            }
                        }, [System.Windows.Threading.DispatcherPriority]::Background, [System.Threading.CancellationToken]::None, [TimeSpan]::FromMilliseconds(100))
                }
                catch [System.TimeoutException] {
                    Write-Verbose "UI log update timed out - skipping"
                }
                catch {
                    Write-Verbose "Dispatcher invoke failed: $($_.Exception.Message)"
                }
            }
            
            # Step 3: Always log to verbose stream as fallback
            Write-Verbose $logEntry
        }
        catch {
            # Fallback logging to prevent log failures from breaking application
            Write-Verbose "Log function error: $($_.Exception.Message). Original message: $Message"
        }
    }
}

<#
.SYNOPSIS
    Updates application progress indicators with thread safety.
    
.DESCRIPTION
    Provides safe progress updates:
    - Thread-safe Dispatcher usage
    - Input validation and sanitization
    - Multiple UI element updates
    - Graceful error handling
    
.PARAMETER Percentage
    Progress percentage (0-100)
    
.PARAMETER StatusMessage
    Status message to display
#>
function Update-ApplicationProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [double]$Percentage,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StatusMessage
    )
    
    process {
        try {
            # Rate limit progress updates to prevent resource exhaustion
            if (-not $script:LastProgressUpdate) {
                $script:LastProgressUpdate = [DateTime]::MinValue
            }
            $timeSinceLastUpdate = ([DateTime]::Now - $script:LastProgressUpdate).TotalMilliseconds
            
            # Only update UI every 500ms unless it's a significant change
            if ($timeSinceLastUpdate -lt 500 -and $Percentage -ne 0 -and $Percentage -ne 100) {
                Write-Verbose "Progress: $($Percentage.ToString("F1"))% - $StatusMessage (UI update skipped for performance)"
                return
            }
            
            $script:LastProgressUpdate = [DateTime]::Now
            
            # Sanitize status message for security
            $sanitizedMessage = if (Get-Command -Name "Protect-SensitiveOutput" -ErrorAction SilentlyContinue) {
                Protect-SensitiveOutput -OutputText $StatusMessage
            }
            else {
                $StatusMessage
            }
            
            # Single UI update with timeout and error handling
            if ($script:MainWindow -and $script:MainWindow.Dispatcher -and -not $script:MainWindow.Dispatcher.HasShutdownStarted) {
                try {
                    $script:MainWindow.Dispatcher.Invoke([System.Action] {
                            try {
                                # Update all progress elements in one operation
                                $progressBar = $script:MainWindow.FindName("MainProgressBar")
                                $statusText = $script:MainWindow.FindName("ProgressTextBlock")
                                $percentText = $script:MainWindow.FindName("ProgressPercentageBlock")
                
                                if ($progressBar -and $progressBar.IsLoaded) {
                                    $progressBar.Value = $Percentage
                                }
                                if ($statusText -and $statusText.IsLoaded) {
                                    $statusText.Text = $sanitizedMessage
                                }
                                if ($percentText -and $percentText.IsLoaded) {
                                    $percentText.Text = "$($Percentage.ToString("F1"))%"
                                }
                            }
                            catch {
                                Write-Verbose "Progress UI update failed: $($_.Exception.Message)"
                            }
                        }, [System.Windows.Threading.DispatcherPriority]::Background, [System.Threading.CancellationToken]::None, [TimeSpan]::FromMilliseconds(100))
                }
                catch [System.TimeoutException] {
                    Write-Verbose "Progress UI update timed out - skipping"
                }
                catch {
                    Write-Verbose "Progress dispatcher invoke failed: $($_.Exception.Message)"
                }
            }
            
            Write-Verbose "Progress: $($Percentage.ToString("F1"))% - $sanitizedMessage"
        }
        catch {
            Write-Verbose "Progress update error: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Updates workflow step indicators in the UI.
    
.DESCRIPTION
    Provides visual workflow progression:
    - Thread-safe step indicator updates
    - Color-coded status representation
    - Accessibility-friendly visual cues
    - Error state handling
    
.PARAMETER Step
    The current workflow step
    
.PARAMETER Status
    The status of the current step
#>
function Update-WorkflowStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Step,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Pending", "Active", "Completed", "Error")]
        [string]$Status = "Active"
    )
    
    process {
        try {
            # Convert step to integer if it's an enum
            $stepValue = if ($Step -is [int]) { $Step } else { [int]$Step }
            
            if ($script:MainWindow -and $script:MainWindow.Dispatcher -and -not $script:MainWindow.Dispatcher.HasShutdownStarted) {
                [void]$script:MainWindow.Dispatcher.BeginInvoke([System.Action] {
                        try {
                            # Define status colors for visual feedback
                            $colors = @{
                                Pending   = [System.Windows.Media.Color]::FromRgb(225, 225, 225)  # Light gray
                                Active    = [System.Windows.Media.Color]::FromRgb(0, 120, 212)    # Blue
                                Completed = [System.Windows.Media.Color]::FromRgb(16, 124, 16)    # Green
                                Error     = [System.Windows.Media.Color]::FromRgb(209, 52, 56)    # Red
                            }
                    
                            # Update each step indicator based on current progress
                            for ($i = 1; $i -le 4; $i++) {
                                $indicator = $script:MainWindow.FindName("Step${i}Indicator")
                                if ($indicator -and $indicator.IsLoaded) {
                                    if ($i -lt $stepValue) {
                                        # Previous steps are completed
                                        $indicator.Background = [System.Windows.Media.SolidColorBrush]::new($colors.Completed)
                                    }
                                    elseif ($i -eq $stepValue) {
                                        # Current step with specified status
                                        $indicator.Background = [System.Windows.Media.SolidColorBrush]::new($colors[$Status])
                                    }
                                    else {
                                        # Future steps are pending
                                        $indicator.Background = [System.Windows.Media.SolidColorBrush]::new($colors.Pending)
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Workflow step update failed: $($_.Exception.Message)"
                        }
                    }, [System.Windows.Threading.DispatcherPriority]::Background)
            }
        }
        catch {
            Write-Verbose "Workflow step update error: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Provides visual feedback through control border animation.
    
.DESCRIPTION
    Creates temporary visual feedback:
    - Animated border color changes
    - Configurable flash duration
    - Smooth color transitions
    - Non-intrusive user feedback
    
.PARAMETER Control
    The UI control to animate
    
.PARAMETER FlashColor
    The color to flash (default: success green)
    
.PARAMETER DurationMs
    Animation duration in milliseconds
#>
function Invoke-ControlBorderFlash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Controls.Control]$Control,

        [Parameter(Mandatory = $false)]
        [System.Windows.Media.Color]$FlashColor = [System.Windows.Media.Color]::FromRgb(16, 124, 16), # Success green

        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 3000)]
        [int]$DurationMs = 750
    )
    
    process {
        try {
            if (-not $Control -or -not $Control.IsLoaded) {
                Write-Verbose "Control not available for border flash animation"
                return
            }
            
            # Store original border brush for restoration
            $originalBrush = $Control.BorderBrush
            $flashBrush = [System.Windows.Media.SolidColorBrush]::new($FlashColor)
            
            # Create smooth color animation
            $animation = [System.Windows.Media.Animation.ColorAnimation]::new()
            $animation.From = $FlashColor
            
            # Determine target color from original brush
            if ($originalBrush -is [System.Windows.Media.SolidColorBrush]) {
                $animation.To = $originalBrush.Color
            }
            else {
                # Fallback to neutral color if original brush is complex
                $animation.To = [System.Windows.Media.Color]::FromRgb(204, 204, 204)
            }
            
            $animation.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds($DurationMs))
            $animation.EasingFunction = [System.Windows.Media.Animation.CubicEase]::new()
            
            # Create and configure storyboard
            $storyboard = [System.Windows.Media.Animation.Storyboard]::new()
            $storyboard.Children.Add($animation)
            
            # Set animation targets
            [System.Windows.Media.Animation.Storyboard]::SetTarget($animation, $Control)
            [System.Windows.Media.Animation.Storyboard]::SetTargetProperty($animation, [System.Windows.PropertyPath]::new("(Control.BorderBrush).(SolidColorBrush.Color)"))
            
            # Apply flash color and start animation
            $Control.BorderBrush = $flashBrush
            $storyboard.Begin()
            
            Write-Verbose "Border flash animation started for control"
        }
        catch {
            Write-Verbose "Failed to invoke control border flash: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Sets comprehensive accessibility properties on UI controls.
    
.DESCRIPTION
    Enhances UI accessibility with:
    - Screen reader friendly names and descriptions
    - Keyboard accelerator key definitions
    - Form validation requirements
    - Compliance with accessibility standards
    
.PARAMETER Control
    The UI control to enhance
    
.PARAMETER Name
    Accessible name for screen readers
    
.PARAMETER HelpText
    Detailed help text for screen readers
    
.PARAMETER AcceleratorKey
    Keyboard shortcut definition
    
.PARAMETER IsRequiredForForm
    Whether the control is required for form completion
#>
function Set-ControlAccessibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.DependencyObject]$Control,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$HelpText,
        
        [Parameter(Mandatory = $false)]
        [string]$AcceleratorKey,
        
        [Parameter(Mandatory = $false)]
        [bool]$IsRequiredForForm = $false
    )
    
    process {
        try {
            if (-not $Control) {
                Write-Warning "Cannot set accessibility properties on null control"
                return
            }
            
            # Set accessible name for screen readers
            [System.Windows.Automation.AutomationProperties]::SetName($Control, $Name)
            
            # Set detailed help text if provided
            if (-not [string]::IsNullOrWhiteSpace($HelpText)) {
                [System.Windows.Automation.AutomationProperties]::SetHelpText($Control, $HelpText)
            }
            
            # Set keyboard accelerator if provided
            if (-not [string]::IsNullOrWhiteSpace($AcceleratorKey)) {
                [System.Windows.Automation.AutomationProperties]::SetAcceleratorKey($Control, $AcceleratorKey)
            }
            
            # Mark as required for form completion if specified
            if ($IsRequiredForForm) {
                [System.Windows.Automation.AutomationProperties]::SetIsRequiredForForm($Control, $true)
            }
            
            Write-Verbose "Accessibility properties set for control: $Name"
        }
        catch {
            Write-Warning "Failed to set accessibility properties for control '$Name': $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Adds smooth micro-interactions to button controls.
    
.DESCRIPTION
    Enhances user experience with:
    - Hover effect animations
    - Smooth scaling transitions
    - Performance-optimized transforms
    - Accessible interaction feedback
    
.PARAMETER Button
    The button control to enhance
    
.PARAMETER AnimationDurationMs
    Duration of hover animations in milliseconds
#>
function Add-ButtonMicroInteractions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Controls.Button]$Button,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(50, 500)]
        [int]$AnimationDurationMs = 150
    )
    
    process {
        try {
            if (-not $Button) {
                Write-Warning "Cannot add micro-interactions to null button"
                return
            }
            
            # Add smooth hover entrance effect
            $Button.Add_MouseEnter({
                    param($buttonSender, $mouseArgs)
            
                    try {
                        if ($buttonSender.IsEnabled) {
                            # Create or get transform group for performance
                            if (-not $buttonSender.RenderTransform -or $buttonSender.RenderTransform -isnot [System.Windows.Media.TransformGroup]) {
                                $transformGroup = [System.Windows.Media.TransformGroup]::new()
                                $scaleTransform = [System.Windows.Media.ScaleTransform]::new()
                                $transformGroup.Children.Add($scaleTransform)
                                $buttonSender.RenderTransform = $transformGroup
                                $buttonSender.RenderTransformOrigin = [System.Windows.Point]::new(0.5, 0.5)
                            }
                    
                            # Apply subtle scale animation for hover feedback
                            $scaleTransform = $buttonSender.RenderTransform.Children[0]
                            $scaleAnimation = [System.Windows.Media.Animation.DoubleAnimation]::new()
                            $scaleAnimation.To = 1.02  # 2% scale increase
                            $scaleAnimation.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds($AnimationDurationMs))
                            $scaleAnimation.EasingFunction = [System.Windows.Media.Animation.CubicEase]::new()
                    
                            # Apply to both X and Y axes for uniform scaling
                            $scaleTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $scaleAnimation)
                            $scaleTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $scaleAnimation)
                        }
                    }
                    catch {
                        Write-Verbose "Hover entrance animation error: $($_.Exception.Message)"
                    }
                })
            
            # Add smooth hover exit effect
            $Button.Add_MouseLeave({
                    param($buttonSender, $mouseArgs)
            
                    try {
                        if ($buttonSender.IsEnabled -and $buttonSender.RenderTransform -is [System.Windows.Media.TransformGroup]) {
                            # Animate back to original scale
                            $scaleTransform = $buttonSender.RenderTransform.Children[0]
                            $scaleAnimation = [System.Windows.Media.Animation.DoubleAnimation]::new()
                            $scaleAnimation.To = 1.0  # Return to original size
                            $scaleAnimation.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds($AnimationDurationMs))
                            $scaleAnimation.EasingFunction = [System.Windows.Media.Animation.CubicEase]::new()
                    
                            # Apply to both X and Y axes
                            $scaleTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $scaleAnimation)
                            $scaleTransform.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $scaleAnimation)
                        }
                    }
                    catch {
                        Write-Verbose "Hover exit animation error: $($_.Exception.Message)"
                    }
                })
            
            Write-Verbose "Micro-interactions added to button successfully"
        }
        catch {
            Write-Warning "Failed to add micro-interactions to button: $($_.Exception.Message)"
        }
    }
}

Write-Verbose "Enhanced UI helper functions loaded successfully"
#endregion

#region 10. Enhanced Windows 11 Fluent Design XAML
<#
.SYNOPSIS
    Complete XAML definition with driver management capabilities including installed driver inventory.
#>

$xamlDefinition = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WIM Driver Studio" 
        Height="700" 
        Width="1100" 
        MinWidth="900"
        MinHeight="650"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResizeWithGrip"
        Background="#F9F9F9"
        FontFamily="Segoe UI Variable Display, Segoe UI, Segoe UI Variable, Arial"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True">
    
    <Window.Resources>
        <!-- Enhanced Windows 11 Fluent Design System Color Palette -->
        <SolidColorBrush x:Key="AccentBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="AccentHoverBrush" Color="#106EBE"/>
        <SolidColorBrush x:Key="AccentPressedBrush" Color="#005A9E"/>
        <SolidColorBrush x:Key="CardBackgroundBrush" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="CardBorderBrush" Color="#E1E1E1"/>
        <SolidColorBrush x:Key="CardHoverBorderBrush" Color="#D1D1D1"/>
        <SolidColorBrush x:Key="TextPrimaryBrush" Color="#323130"/>
        <SolidColorBrush x:Key="TextSecondaryBrush" Color="#605E5C"/>
        <SolidColorBrush x:Key="TextTertiaryBrush" Color="#8A8886"/>
        <SolidColorBrush x:Key="ControlBackgroundBrush" Color="#FAFAFA"/>
        <SolidColorBrush x:Key="ControlBorderBrush" Color="#CCCCCC"/>
        <SolidColorBrush x:Key="SuccessBrush" Color="#107C10"/>
        <SolidColorBrush x:Key="SuccessBackgroundBrush" Color="#F3FFF3"/>
        <SolidColorBrush x:Key="ErrorBrush" Color="#D13438"/>
        <SolidColorBrush x:Key="WarningBrush" Color="#FF8C00"/>
        <SolidColorBrush x:Key="InfoBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="DangerBrush" Color="#D13438"/>
        <SolidColorBrush x:Key="SidebarBackgroundBrush">
            <SolidColorBrush.Color>
                <Color A="255" R="243" G="243" B="243"/>
            </SolidColorBrush.Color>
        </SolidColorBrush>

        <!-- Enhanced Gradient Brushes for Modern Look -->
        <LinearGradientBrush x:Key="AccentGradientBrush" StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#0078D4" Offset="0"/>
            <GradientStop Color="#106EBE" Offset="1"/>
        </LinearGradientBrush>
        
        <LinearGradientBrush x:Key="SuccessGradientBrush" StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#107C10" Offset="0"/>
            <GradientStop Color="#0E6B0E" Offset="1"/>
        </LinearGradientBrush>

        <LinearGradientBrush x:Key="DangerGradientBrush" StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#D13438" Offset="0"/>
            <GradientStop Color="#B02A2E" Offset="1"/>
        </LinearGradientBrush>
        
        <LinearGradientBrush x:Key="SidebarGradientBrush" StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#F3F3F3" Offset="0"/>
            <GradientStop Color="#F8F8F8" Offset="1"/>
        </LinearGradientBrush>

        <!-- Enhanced Fluent Card Style -->
        <Style x:Key="FluentCard" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="24"/>
            <Setter Property="Margin" Value="0,0,0,20"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="{StaticResource CardBorderBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#1A000000" Direction="270" ShadowDepth="2" BlurRadius="16" Opacity="0.1"/>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="BorderBrush" Value="{StaticResource CardHoverBorderBrush}"/>
                    <Setter Property="Effect">
                        <Setter.Value>
                            <DropShadowEffect Color="#1A000000" Direction="270" ShadowDepth="4" BlurRadius="20" Opacity="0.15"/>
                        </Setter.Value>
                    </Setter>
                    <Setter Property="RenderTransform">
                        <Setter.Value>
                            <TranslateTransform Y="-1"/>
                        </Setter.Value>
                    </Setter>
                </Trigger>
            </Style.Triggers>
        </Style>
        
        <!-- Enhanced Primary Button Style -->
        <Style x:Key="FluentPrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource AccentGradientBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="20,12"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="MinHeight" Value="40"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4D0078D4" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.35"/>
                </Setter.Value>
            </Setter>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" 
                                Background="{TemplateBinding Background}" 
                                CornerRadius="8"
                                Padding="{TemplateBinding Padding}">
                            <Border.RenderTransform>
                                <ScaleTransform ScaleX="1" ScaleY="1"/>
                            </Border.RenderTransform>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock x:Name="IconText" 
                                           Grid.Column="0"
                                           FontFamily="Segoe MDL2 Assets" 
                                           FontSize="16"
                                           Margin="0,0,8,0"
                                           VerticalAlignment="Center"
                                           Visibility="Collapsed"/>
                                <ContentPresenter Grid.Column="1" 
                                                  HorizontalAlignment="Center" 
                                                  VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Color="#4D0078D4" Direction="270" ShadowDepth="5" BlurRadius="16" Opacity="0.5"/>
                                    </Setter.Value>
                                </Setter>
                                <Trigger.EnterActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleX" 
                                                           To="1.03" Duration="0:0:0.2"/>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleY" 
                                                           To="1.03" Duration="0:0:0.2"/>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.EnterActions>
                                <Trigger.ExitActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleX" 
                                                           To="1.0" Duration="0:0:0.2"/>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleY" 
                                                           To="1.0" Duration="0:0:0.2"/>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentPressedBrush}"/>
                                <Setter TargetName="border" Property="RenderTransform">
                                    <Setter.Value>
                                        <ScaleTransform ScaleX="0.97" ScaleY="0.97"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Background" Value="#E0E0E0"/>
                                <Setter Property="Foreground" Value="#A0A0A0"/>
                                <Setter Property="Effect" Value="{x:Null}"/>
                                <Setter Property="Opacity" Value="0.6"/>
                            </Trigger>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter TargetName="border" Property="BorderThickness" Value="3"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- Success Button Style -->
        <Style x:Key="FluentSuccessButton" TargetType="Button" BasedOn="{StaticResource FluentPrimaryButton}">
            <Setter Property="Background" Value="{StaticResource SuccessGradientBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4D107C10" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.35"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Warning Button Style -->
        <Style x:Key="FluentWarningButton" TargetType="Button" BasedOn="{StaticResource FluentPrimaryButton}">
            <Setter Property="Background">
                <Setter.Value>
                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                        <GradientStop Color="#FF8C00" Offset="0"/>
                        <GradientStop Color="#FF7700" Offset="1"/>
                    </LinearGradientBrush>
                </Setter.Value>
            </Setter>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4DFF8C00" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.35"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Danger Button Style -->
        <Style x:Key="FluentDangerButton" TargetType="Button" BasedOn="{StaticResource FluentPrimaryButton}">
            <Setter Property="Background" Value="{StaticResource DangerGradientBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4DD13438" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.35"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Enhanced Secondary Button Style with Better Spacing -->
        <Style x:Key="FluentSecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="BorderThickness" Value="2"/>
            <Setter Property="BorderBrush" Value="{StaticResource ControlBorderBrush}"/>
            <Setter Property="Padding" Value="18,10"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="Medium"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="MinHeight" Value="36"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" 
                                Background="{TemplateBinding Background}" 
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <Border.RenderTransform>
                                <ScaleTransform ScaleX="1" ScaleY="1"/>
                            </Border.RenderTransform>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock x:Name="IconText" 
                                           Grid.Column="0"
                                           FontFamily="Segoe MDL2 Assets" 
                                           FontSize="14"
                                           Margin="0,0,6,0"
                                           VerticalAlignment="Center"
                                           Visibility="Collapsed"/>
                                <ContentPresenter Grid.Column="1" 
                                                  HorizontalAlignment="Center" 
                                                  VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#F0F0F0"/>
                                <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                                <Setter Property="BorderThickness" Value="2"/>
                                <Trigger.EnterActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleX" 
                                                           To="1.02" Duration="0:0:0.15"/>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleY" 
                                                           To="1.02" Duration="0:0:0.15"/>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.EnterActions>
                                <Trigger.ExitActions>
                                    <BeginStoryboard>
                                        <Storyboard>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleX" 
                                                           To="1.0" Duration="0:0:0.15"/>
                                            <DoubleAnimation Storyboard.TargetName="border" 
                                                           Storyboard.TargetProperty="RenderTransform.ScaleY" 
                                                           To="1.0" Duration="0:0:0.15"/>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.ExitActions>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#E8E8E8"/>
                                <Setter TargetName="border" Property="RenderTransform">
                                    <Setter.Value>
                                        <ScaleTransform ScaleX="0.98" ScaleY="0.98"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#F5F5F5"/>
                                <Setter Property="Foreground" Value="#C0C0C0"/>
                                <Setter Property="BorderBrush" Value="#E0E0E0"/>
                                <Setter Property="Opacity" Value="0.6"/>
                            </Trigger>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                                <Setter Property="BorderThickness" Value="3"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- Enhanced TextBox Style -->
        <Style x:Key="FluentTextBox" TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource ControlBorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,10"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="border" 
                                Background="{TemplateBinding Background}" 
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ScrollViewer x:Name="PART_ContentHost" 
                                          Padding="{TemplateBinding Padding}"
                                          VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                                <Setter TargetName="border" Property="BorderThickness" Value="2"/>
                                <Setter Property="Padding" Value="11,9"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                            </Trigger>
                            <Trigger Property="IsReadOnly" Value="True">
                                <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- Enhanced Step Indicator Style -->
        <Style x:Key="StepIndicator" TargetType="Border">
            <Setter Property="Width" Value="36"/>
            <Setter Property="Height" Value="36"/>
            <Setter Property="CornerRadius" Value="18"/>
            <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
            <Setter Property="BorderThickness" Value="2"/>
            <Setter Property="BorderBrush" Value="{StaticResource ControlBorderBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#1A000000" Direction="270" ShadowDepth="2" BlurRadius="8" Opacity="0.1"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Enhanced Step Indicator Active State -->
        <Style x:Key="StepIndicatorActive" TargetType="Border" BasedOn="{StaticResource StepIndicator}">
            <Setter Property="Background" Value="{StaticResource AccentGradientBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4D0078D4" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.3"/>
                </Setter.Value>
            </Setter>
            <Setter Property="RenderTransform">
                <Setter.Value>
                    <ScaleTransform ScaleX="1.05" ScaleY="1.05"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Enhanced Step Indicator Completed State -->
        <Style x:Key="StepIndicatorCompleted" TargetType="Border" BasedOn="{StaticResource StepIndicator}">
            <Setter Property="Background" Value="{StaticResource SuccessGradientBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource SuccessBrush}"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#4D107C10" Direction="270" ShadowDepth="3" BlurRadius="12" Opacity="0.3"/>
                </Setter.Value>
            </Setter>
        </Style>
        
        <!-- Enhanced Typography Styles -->
        <Style x:Key="TitleTextStyle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="28"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        </Style>
        
        <Style x:Key="SubtitleTextStyle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
        </Style>
        
        <Style x:Key="SectionHeaderStyle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="20"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Margin" Value="0,0,0,12"/>
        </Style>
        
        <Style x:Key="BodyTextStyle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
            <Setter Property="LineHeight" Value="20"/>
            <Setter Property="TextWrapping" Value="Wrap"/>
        </Style>

        <!-- Enhanced Status Message Style -->
        <Style x:Key="StatusMessageStyle" TargetType="Border">
            <Setter Property="CornerRadius" Value="6"/>
            <Setter Property="Padding" Value="12"/>
            <Setter Property="Margin" Value="0,12,0,0"/>
            <Setter Property="BorderThickness" Value="0,0,0,4"/>
        </Style>

        <!-- Success Status Style -->
        <Style x:Key="SuccessStatusStyle" TargetType="Border" BasedOn="{StaticResource StatusMessageStyle}">
            <Setter Property="Background" Value="{StaticResource SuccessBackgroundBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource SuccessBrush}"/>
        </Style>
        
        <!-- Enhanced CheckBox Style -->
        <Style x:Key="FluentCheckBox" TargetType="CheckBox">
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
        </Style>
        
        <!-- Enhanced ProgressBar Style -->
        <Style x:Key="FluentProgressBar" TargetType="ProgressBar">
            <Setter Property="Height" Value="6"/>
            <Setter Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource AccentGradientBrush}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Border Background="{TemplateBinding Background}" CornerRadius="3">
                            <Border x:Name="PART_Track" CornerRadius="3">
                                <Border x:Name="PART_Indicator" 
                                        Background="{TemplateBinding Foreground}" 
                                        HorizontalAlignment="Left" 
                                        CornerRadius="3"/>
                            </Border>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Custom TabControl Style for Driver Management -->
        <Style x:Key="FluentTabControl" TargetType="TabControl">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="0"/>
            <Setter Property="Margin" Value="0"/>
        </Style>

        <Style x:Key="FluentTabItem" TargetType="TabItem">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,12"/>
            <Setter Property="Margin" Value="0,0,4,0"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="Medium"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border x:Name="Border" 
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6,6,0,0"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter x:Name="ContentSite"
                                              VerticalAlignment="Center"
                                              HorizontalAlignment="Center"
                                              ContentSource="Header"
                                              Margin="0"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource CardBackgroundBrush}"/>
                                <Setter TargetName="Border" Property="BorderThickness" Value="1,1,1,0"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource CardBorderBrush}"/>
                                <Setter Property="Foreground" Value="{StaticResource AccentBrush}"/>
                                <Setter Property="FontWeight" Value="SemiBold"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource ControlBackgroundBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Custom Expander Style -->
        <Style x:Key="FluentExpanderStyle" TargetType="Expander">
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Expander">
                        <StackPanel>
                            <Border x:Name="HeaderBorder" Background="Transparent" Padding="0,8">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto" />
                                        <ColumnDefinition Width="*" />
                                    </Grid.ColumnDefinitions>
                                    <ToggleButton x:Name="HeaderToggleButton"
                                                  Grid.Column="0"
                                                  IsChecked="{Binding IsExpanded, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay}"
                                                  Style="{StaticResource {x:Type ToggleButton}}">
                                        <ToggleButton.Template>
                                            <ControlTemplate TargetType="ToggleButton">
                                                <Border Background="Transparent" Padding="4">
                                                    <TextBlock x:Name="Arrow"
                                                               Text="&#xE76C;"
                                                               FontFamily="Segoe MDL2 Assets"
                                                               FontSize="12"
                                                               Foreground="{StaticResource TextSecondaryBrush}"
                                                               VerticalAlignment="Center" />
                                                </Border>
                                                <ControlTemplate.Triggers>
                                                    <Trigger Property="IsChecked" Value="True">
                                                        <Setter TargetName="Arrow" Property="Text" Value="&#xE70D;" />
                                                    </Trigger>
                                                </ControlTemplate.Triggers>
                                            </ControlTemplate>
                                        </ToggleButton.Template>
                                    </ToggleButton>
                                    <ContentPresenter Grid.Column="1"
                                                      ContentSource="Header"
                                                      VerticalAlignment="Center"
                                                      HorizontalAlignment="Left"
                                                      RecognizesAccessKey="True" />
                                </Grid>
                            </Border>
                            <ContentPresenter x:Name="ExpandSite"
                                              Visibility="Collapsed"
                                              Focusable="False"
                                              Margin="0,4,0,0"/>
                        </StackPanel>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsExpanded" Value="True">
                                <Setter TargetName="ExpandSite" Property="Visibility" Value="Visible" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- File Type Indicator Styles -->
        <Style x:Key="FileTypeSupported" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource SuccessBrush}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Margin" Value="0,0,0,4"/>
        </Style>

        <Style x:Key="FileTypeWarning" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource WarningBrush}"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontStyle" Value="Italic"/>
        </Style>
    </Window.Resources>
    
    <!-- Main application layout -->
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="320" MinWidth="300"/>
            <ColumnDefinition Width="*" MinWidth="580"/>
        </Grid.ColumnDefinitions>
        
        <!-- Enhanced Sidebar -->
        <Border Grid.Column="0" 
                Background="{StaticResource SidebarGradientBrush}" 
                Padding="24,28"
                BorderThickness="0,0,1,0"
                BorderBrush="{StaticResource CardBorderBrush}">
            
            <StackPanel>
                <!-- Enhanced Application Header -->
                <StackPanel Margin="0,0,0,32">
                    <TextBlock Text="WIM Driver Studio" Style="{StaticResource TitleTextStyle}" Margin="0,0,0,6"/>
                    <TextBlock Text="Driver injection and management" Style="{StaticResource SubtitleTextStyle}"/>
                    
                    <!-- Enhanced Status Block -->
                    <Border x:Name="SecurityStatusContainer" Style="{StaticResource SuccessStatusStyle}">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Grid.Column="0" 
                                       Text="&#xE74E;" 
                                       FontFamily="Segoe MDL2 Assets"
                                       FontSize="14" 
                                       Margin="0,0,8,0"
                                       VerticalAlignment="Center"/>
                            <TextBlock x:Name="SecurityStatusBlock" 
                                       Grid.Column="1"
                                       Text="Ready for secure driver operations" 
                                       FontSize="13"
                                       FontWeight="SemiBold"
                                       Foreground="{StaticResource SuccessBrush}"
                                       TextWrapping="Wrap"
                                       VerticalAlignment="Center"/>
                        </Grid>
                    </Border>
                </StackPanel>
                
                <!-- Enhanced Workflow Steps -->
                <StackPanel x:Name="WorkflowSteps" Margin="0,0,0,32">
                    <!-- Step 1: Select WIM File -->
                    <Grid Margin="0,0,0,20">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="44"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <Border x:Name="Step1Indicator" 
                                Grid.Column="0" 
                                Style="{StaticResource StepIndicatorActive}">
                            <TextBlock Text="1" 
                                       Foreground="White" 
                                       FontWeight="SemiBold" 
                                       FontSize="14" 
                                       HorizontalAlignment="Center" 
                                       VerticalAlignment="Center"/>
                        </Border>
                        
                        <StackPanel Grid.Column="1" Margin="16,0,0,0">
                            <TextBlock Text="Select WIM File" 
                                       FontWeight="SemiBold" 
                                       FontSize="15" 
                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                            <TextBlock Text="Choose Windows image file" 
                                       Style="{StaticResource BodyTextStyle}" 
                                       FontSize="13" 
                                       Margin="0,4,0,0"/>
                        </StackPanel>
                    </Grid>
                    
                    <!-- Step 2: Select Drivers -->
                    <Grid Margin="0,0,0,20">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="44"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <Border x:Name="Step2Indicator" Grid.Column="0" Style="{StaticResource StepIndicator}">
                            <TextBlock Text="2" 
                                       FontWeight="SemiBold" 
                                       FontSize="14" 
                                       HorizontalAlignment="Center" 
                                       VerticalAlignment="Center"/>
                        </Border>
                        
                        <StackPanel Grid.Column="1" Margin="16,0,0,0">
                            <TextBlock Text="Manage Drivers" 
                                       FontWeight="SemiBold" 
                                       FontSize="15" 
                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                            <TextBlock Text="Add/remove driver packages" 
                                       Style="{StaticResource BodyTextStyle}" 
                                       FontSize="13" 
                                       Margin="0,4,0,0"/>
                        </StackPanel>
                    </Grid>
                    
                    <!-- Step 3: Configure Options -->
                    <Grid Margin="0,0,0,20">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="44"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <Border x:Name="Step3Indicator" Grid.Column="0" Style="{StaticResource StepIndicator}">
                            <TextBlock Text="3" 
                                       FontWeight="SemiBold" 
                                       FontSize="14" 
                                       HorizontalAlignment="Center" 
                                       VerticalAlignment="Center"/>
                        </Border>
                        
                        <StackPanel Grid.Column="1" Margin="16,0,0,0">
                            <TextBlock Text="Configure Options" 
                                       FontWeight="SemiBold" 
                                       FontSize="15" 
                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                            <TextBlock Text="Set mount directory" 
                                       Style="{StaticResource BodyTextStyle}" 
                                       FontSize="13" 
                                       Margin="0,4,0,0"/>
                        </StackPanel>
                    </Grid>
                    
                    <!-- Step 4: Process Images -->
                    <Grid Margin="0,0,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="44"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        
                        <Border x:Name="Step4Indicator" Grid.Column="0" Style="{StaticResource StepIndicator}">
                            <TextBlock Text="4" 
                                       FontWeight="SemiBold" 
                                       FontSize="14" 
                                       HorizontalAlignment="Center" 
                                       VerticalAlignment="Center"/>
                        </Border>
                        
                        <StackPanel Grid.Column="1" Margin="16,0,0,0">
                            <TextBlock Text="Process Images" 
                                       FontWeight="SemiBold" 
                                       FontSize="15" 
                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                            <TextBlock Text="Execute operations" 
                                       Style="{StaticResource BodyTextStyle}" 
                                       FontSize="13" 
                                       Margin="0,4,0,0"/>
                        </StackPanel>
                    </Grid>
                </StackPanel>
                
                <!-- Enhanced Action Buttons -->
                <StackPanel>
                    <Button x:Name="StartButton" 
                            Style="{StaticResource FluentPrimaryButton}" 
                            Margin="0,0,0,12"
                            AutomationProperties.Name="Start driver management process"
                            AutomationProperties.HelpText="Begin the driver management process with selected WIM file"
                            AutomationProperties.AcceleratorKey="Alt+Enter"
                            KeyboardNavigation.TabIndex="1">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock FontFamily="Segoe MDL2 Assets" 
                                       Text="&#xE768;" 
                                       FontSize="14" 
                                       Margin="0,0,6,0"
                                       VerticalAlignment="Center"/>
                            <TextBlock Text="Start Process" 
                                       FontSize="14"
                                       FontWeight="SemiBold"
                                       VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                    <Button x:Name="CancelButton" 
                            Style="{StaticResource FluentSecondaryButton}" 
                            AutomationProperties.Name="Cancel operation"
                            AutomationProperties.HelpText="Cancel the current operation or exit the application"
                            AutomationProperties.AcceleratorKey="Escape"
                            KeyboardNavigation.TabIndex="2">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock FontFamily="Segoe MDL2 Assets" 
                                       Text="&#xE711;" 
                                       FontSize="12" 
                                       Margin="0,0,5,0"
                                       VerticalAlignment="Center"/>
                            <TextBlock Text="Cancel" 
                                       VerticalAlignment="Center"/>
                        </StackPanel>
                    </Button>
                </StackPanel>
            </StackPanel>
        </Border>
        
        <!-- Enhanced Main Content Area with Driver Management -->
        <Border Grid.Column="1" Background="#F9F9F9">
            <ScrollViewer VerticalScrollBarVisibility="Auto" 
                          HorizontalScrollBarVisibility="Disabled"
                          Padding="28">
                <StackPanel>
                    <!-- Enhanced WIM File Selection Card -->
                    <Border Style="{StaticResource FluentCard}">
                        <StackPanel>
                            <Grid Margin="0,0,0,16">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0"
                                           Text="&#xE74E;" 
                                           FontFamily="Segoe MDL2 Assets"
                                           FontSize="16" 
                                           Margin="0,0,8,0"
                                           VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="1"
                                           Text="Windows Image File Selection" 
                                           Style="{StaticResource SectionHeaderStyle}"
                                           Margin="0"
                                           VerticalAlignment="Center"
                                           AutomationProperties.HeadingLevel="2"/>
                            </Grid>
                            
                            <TextBlock Text="Select the WIM file you want to modify. The tool will provide driver management capabilities for all available indexes." 
                                       Style="{StaticResource BodyTextStyle}" 
                                       Margin="0,0,0,12"/>
                            
                            <!-- Enhanced File Types Section -->
                            <StackPanel Margin="0,0,0,16">
                                <TextBlock Text="Supported Files:" 
                                           FontWeight="SemiBold" 
                                           FontSize="14" 
                                           Foreground="{StaticResource TextPrimaryBrush}" 
                                           Margin="0,0,0,6"/>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                                    <TextBlock Text="&#xE73E;" 
                                               FontFamily="Segoe MDL2 Assets"
                                               Foreground="{StaticResource SuccessBrush}" 
                                               Margin="0,0,6,0" 
                                               VerticalAlignment="Center"/>
                                    <TextBlock Text="boot.wim - Windows PE and Setup environments" 
                                               Style="{StaticResource FileTypeSupported}"/>
                                </StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                                    <TextBlock Text="&#xE73E;" 
                                               FontFamily="Segoe MDL2 Assets"
                                               Foreground="{StaticResource SuccessBrush}" 
                                               Margin="0,0,6,0" 
                                               VerticalAlignment="Center"/>
                                    <TextBlock Text="install.wim - Windows installation images" 
                                               Style="{StaticResource FileTypeSupported}"/>
                                </StackPanel>
                                <StackPanel Orientation="Horizontal">
                                    <TextBlock Text="&#xE7BA;" 
                                               FontFamily="Segoe MDL2 Assets"
                                               Foreground="{StaticResource WarningBrush}" 
                                               Margin="0,0,6,0" 
                                               VerticalAlignment="Center"/>
                                    <TextBlock Text="install.wim files require more processing time" 
                                               Style="{StaticResource FileTypeWarning}"/>
                                </StackPanel>
                            </StackPanel>
                            
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="WimFileTextBox" 
                                         Style="{StaticResource FluentTextBox}" 
                                         IsReadOnly="True" 
                                         Text="No WIM file selected..."
                                         Margin="0,0,12,0"
                                         AutomationProperties.Name="Selected WIM file path"
                                         AutomationProperties.HelpText="Path to the Windows image file that will be modified"
                                         AutomationProperties.IsRequiredForForm="True"
                                         KeyboardNavigation.TabIndex="3"/>
                                <Button x:Name="BrowseWimButton" 
                                        Grid.Column="1" 
                                        Style="{StaticResource FluentSecondaryButton}" 
                                        MinWidth="100"
                                        Margin="0,0,12,0"
                                        AutomationProperties.Name="Browse for WIM file"
                                        AutomationProperties.HelpText="Click to select a Windows image file"
                                        AutomationProperties.AcceleratorKey="Alt+B"
                                        KeyboardNavigation.TabIndex="4">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                   Text="&#xE8B7;" 
                                                   FontSize="12" 
                                                   Margin="0,0,5,0"
                                                   VerticalAlignment="Center"/>
                                        <TextBlock Text="Browse" VerticalAlignment="Center"/>
                                    </StackPanel>
                                </Button>
                                <Button x:Name="InventoryDriversButton" 
                                        Grid.Column="2" 
                                        Style="{StaticResource FluentPrimaryButton}" 
                                        MinWidth="140"
                                        IsEnabled="False"
                                        AutomationProperties.Name="Inventory installed drivers"
                                        AutomationProperties.HelpText="Click to scan installed drivers in the WIM file"
                                        KeyboardNavigation.TabIndex="5">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                   Text="&#xE8FD;" 
                                                   FontSize="14" 
                                                   Margin="0,0,6,0"
                                                   VerticalAlignment="Center"/>
                                        <TextBlock Text="Inventory Drivers" 
                                                   FontSize="13"
                                                   FontWeight="SemiBold"
                                                   VerticalAlignment="Center"/>
                                    </StackPanel>
                                </Button>
                            </Grid>
                        </StackPanel>
                    </Border>
                    
                    <!-- Enhanced Driver Management Card with TabControl -->
                    <Border x:Name="DriverManagementCard" Style="{StaticResource FluentCard}">
                        <StackPanel>
                            <Grid Margin="0,0,0,20">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0"
                                           Text="&#xE713;" 
                                           FontFamily="Segoe MDL2 Assets"
                                           FontSize="16" 
                                           Margin="0,0,8,0"
                                           VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="1"
                                           Text="Driver Management" 
                                           Style="{StaticResource SectionHeaderStyle}"
                                           Margin="0"
                                           VerticalAlignment="Center"
                                           AutomationProperties.HeadingLevel="2"/>
                            </Grid>
                            
                            <TabControl x:Name="DriverTabControl" Style="{StaticResource FluentTabControl}">
                                <!-- Add New Drivers Tab -->
                                <TabItem Header="Add Drivers" Style="{StaticResource FluentTabItem}">
                                    <Border Background="{StaticResource CardBackgroundBrush}" 
                                            BorderThickness="1,0,1,1" 
                                            BorderBrush="{StaticResource CardBorderBrush}" 
                                            CornerRadius="0,0,8,8" 
                                            Padding="20">
                                        <StackPanel>
                                            <TextBlock Text="Add new driver packages to the selected WIM image." 
                                                       Style="{StaticResource BodyTextStyle}" 
                                                       Margin="0,0,0,16"/>
                                            
                                            <TextBlock x:Name="DriverPrereqHint"
                                                       Text="[i] Select a WIM file above first - driver suitability is judged against the chosen image (boot.wim vs install.wim)."
                                                       FontSize="12"
                                                       FontStyle="Italic"
                                                       Foreground="{StaticResource TextTertiaryBrush}"
                                                       Margin="0,0,0,12"
                                                       TextWrapping="Wrap"/>
                                            
                                            <Grid Margin="0,0,0,16">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                </Grid.ColumnDefinitions>
                                                <TextBox x:Name="DriverFolderTextBox" 
                                                         Style="{StaticResource FluentTextBox}" 
                                                         IsReadOnly="True" 
                                                         Text="No folder selected..."
                                                         Margin="0,0,12,0"
                                                         AutomationProperties.Name="Selected driver folder path"
                                                         AutomationProperties.HelpText="Path to the folder containing driver packages"
                                                         KeyboardNavigation.TabIndex="6"/>
                                                <Button x:Name="BrowseDriverButton" 
                                                        Grid.Column="1" 
                                                        Style="{StaticResource FluentSecondaryButton}" 
                                                        MinWidth="100"
                                                        IsEnabled="False"
                                                        Margin="0,0,12,0"
                                                        AutomationProperties.Name="Browse for driver folder"
                                                        AutomationProperties.HelpText="Click to select a folder containing driver packages"
                                                        AutomationProperties.AcceleratorKey="Alt+D"
                                                        KeyboardNavigation.TabIndex="7">
                                                    <StackPanel Orientation="Horizontal">
                                                        <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                   Text="&#xE8B7;" 
                                                                   FontSize="12" 
                                                                   Margin="0,0,5,0"
                                                                   VerticalAlignment="Center"/>
                                                        <TextBlock Text="Browse" VerticalAlignment="Center"/>
                                                    </StackPanel>
                                                </Button>
                                                <Button x:Name="ScanDriversButton" 
                                                        Grid.Column="2" 
                                                        Style="{StaticResource FluentPrimaryButton}" 
                                                        MinWidth="120"
                                                        IsEnabled="False"
                                                        AutomationProperties.Name="Scan for drivers"
                                                        AutomationProperties.HelpText="Click to scan the selected folder for driver packages"
                                                        AutomationProperties.AcceleratorKey="Alt+S"
                                                        KeyboardNavigation.TabIndex="8">
                                                    <StackPanel Orientation="Horizontal">
                                                        <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                   Text="&#xE721;" 
                                                                   FontSize="14" 
                                                                   Margin="0,0,6,0"
                                                                   VerticalAlignment="Center"/>
                                                        <TextBlock Text="Scan Drivers" 
                                                                   FontSize="13"
                                                                   FontWeight="SemiBold"
                                                                   VerticalAlignment="Center"/>
                                                    </StackPanel>
                                                </Button>
                                            </Grid>
                                            
                                            <!-- Driver Selection Area -->
                                            <Border x:Name="DriverSelectionCard" Visibility="Collapsed">
                                                <StackPanel>
                                                    <Grid Margin="0,0,0,16">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="*"/>
                                                            <ColumnDefinition Width="Auto"/>
                                                        </Grid.ColumnDefinitions>
                                                        
                                                        <TextBlock x:Name="DriverSummaryText" 
                                                                   Grid.Column="0"
                                                                   Text="Select drivers to inject into the WIM image:" 
                                                                   Style="{StaticResource BodyTextStyle}" 
                                                                   VerticalAlignment="Center"/>
                                                        
                                                        <StackPanel Grid.Column="1" Orientation="Horizontal">
                                                            <Button x:Name="SelectAllDriversButton" 
                                                                    Style="{StaticResource FluentSecondaryButton}" 
                                                                    MinWidth="110"
                                                                    Margin="0,0,16,0"
                                                                    AutomationProperties.Name="Select all drivers"
                                                                    KeyboardNavigation.TabIndex="9">
                                                                <StackPanel Orientation="Horizontal">
                                                                    <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                               Text="&#xE8B3;" 
                                                                               FontSize="12" 
                                                                               Margin="0,0,6,0"
                                                                               VerticalAlignment="Center"/>
                                                                    <TextBlock Text="Select All" 
                                                                               FontSize="13"
                                                                               VerticalAlignment="Center"/>
                                                                </StackPanel>
                                                            </Button>
                                                            <Button x:Name="DeselectAllDriversButton" 
                                                                    Style="{StaticResource FluentSecondaryButton}" 
                                                                    MinWidth="120"
                                                                    AutomationProperties.Name="Deselect all drivers"
                                                                    KeyboardNavigation.TabIndex="10">
                                                                <StackPanel Orientation="Horizontal">
                                                                    <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                               Text="&#xE8BB;" 
                                                                               FontSize="12" 
                                                                               Margin="0,0,6,0"
                                                                               VerticalAlignment="Center"/>
                                                                    <TextBlock Text="Deselect All" 
                                                                               FontSize="13"
                                                                               VerticalAlignment="Center"/>
                                                                </StackPanel>
                                                            </Button>
                                                        </StackPanel>
                                                    </Grid>
                                                    
                                                    <Border Background="{StaticResource ControlBackgroundBrush}" 
                                                            CornerRadius="6" 
                                                            BorderThickness="1" 
                                                            BorderBrush="{StaticResource ControlBorderBrush}"
                                                            MaxHeight="280">
                                                        <ScrollViewer VerticalScrollBarVisibility="Auto" 
                                                                      HorizontalScrollBarVisibility="Disabled"
                                                                      Padding="12">
                                                            <StackPanel x:Name="DriverListPanel"/>
                                                        </ScrollViewer>
                                                    </Border>
                                                    
                                                    <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                                                        <TextBlock x:Name="SelectedDriverCount" 
                                                                   Text="0 drivers selected" 
                                                                   Style="{StaticResource BodyTextStyle}"
                                                                   VerticalAlignment="Center"/>
                                                        <TextBlock Text=" - " 
                                                                   Style="{StaticResource BodyTextStyle}"
                                                                   Margin="12,0"
                                                                   VerticalAlignment="Center"/>
                                                        <TextBlock x:Name="UnsignedDriverWarning" 
                                                                   Text="0 unsigned drivers detected" 
                                                                   Style="{StaticResource BodyTextStyle}"
                                                                   Foreground="{StaticResource ErrorBrush}"
                                                                   VerticalAlignment="Center"/>
                                                    </StackPanel>
                                                </StackPanel>
                                            </Border>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                
                                <!-- Installed Drivers Tab -->
                                <TabItem Header="Installed Drivers" Style="{StaticResource FluentTabItem}">
                                    <Border Background="{StaticResource CardBackgroundBrush}" 
                                            BorderThickness="1,0,1,1" 
                                            BorderBrush="{StaticResource CardBorderBrush}" 
                                            CornerRadius="0,0,8,8" 
                                            Padding="20">
                                        <StackPanel>
                                            <Grid Margin="0,0,0,16">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                </Grid.ColumnDefinitions>
                                                
                                                <TextBlock Grid.Column="0"
                                                           Text="View and manage drivers currently installed in the WIM image." 
                                                           Style="{StaticResource BodyTextStyle}" 
                                                           VerticalAlignment="Center"/>
                                                
                                                <StackPanel Grid.Column="1" Orientation="Horizontal">
                                                    <Button x:Name="ExportDriversButton" 
                                                            Style="{StaticResource FluentSecondaryButton}" 
                                                            MinWidth="120"
                                                            Margin="0,0,16,0"
                                                            IsEnabled="False"
                                                            AutomationProperties.Name="Export selected drivers"
                                                            KeyboardNavigation.TabIndex="11">
                                                        <StackPanel Orientation="Horizontal">
                                                            <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                       Text="&#xE896;" 
                                                                       FontSize="12" 
                                                                       Margin="0,0,6,0"
                                                                       VerticalAlignment="Center"/>
                                                            <TextBlock Text="Export Drivers" 
                                                                       FontSize="13"
                                                                       VerticalAlignment="Center"/>
                                                        </StackPanel>
                                                    </Button>
                                                    <Button x:Name="RemoveDriversButton" 
                                                            Style="{StaticResource FluentDangerButton}" 
                                                            MinWidth="130"
                                                            IsEnabled="False"
                                                            AutomationProperties.Name="Remove selected drivers"
                                                            KeyboardNavigation.TabIndex="12">
                                                        <StackPanel Orientation="Horizontal">
                                                            <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                                       Text="&#xE74D;" 
                                                                       FontSize="12" 
                                                                       Margin="0,0,6,0"
                                                                       VerticalAlignment="Center"/>
                                                            <TextBlock Text="Remove Drivers" 
                                                                       FontSize="13"
                                                                       FontWeight="SemiBold"
                                                                       VerticalAlignment="Center"/>
                                                        </StackPanel>
                                                    </Button>
                                                </StackPanel>
                                            </Grid>
                                            
                                            <Border Background="{StaticResource ControlBackgroundBrush}" 
                                                    CornerRadius="6" 
                                                    BorderThickness="1" 
                                                    BorderBrush="{StaticResource ControlBorderBrush}"
                                                    MaxHeight="320">
                                                <ScrollViewer VerticalScrollBarVisibility="Auto" 
                                                              HorizontalScrollBarVisibility="Disabled"
                                                              Padding="12">
                                                    <StackPanel x:Name="InstalledDriverListPanel">
                                                        <TextBlock Text="No WIM file loaded. Please select a WIM file and click 'Inventory Drivers' to view installed drivers." 
                                                                   Style="{StaticResource BodyTextStyle}"
                                                                   HorizontalAlignment="Center"
                                                                   Margin="20"
                                                                   Foreground="{StaticResource TextTertiaryBrush}"/>
                                                    </StackPanel>
                                                </ScrollViewer>
                                            </Border>
                                            
                                            <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                                                <TextBlock x:Name="InstalledDriverCount" 
                                                           Text="0 drivers installed" 
                                                           Style="{StaticResource BodyTextStyle}"
                                                           VerticalAlignment="Center"/>
                                                <TextBlock Text=" - " 
                                                           Style="{StaticResource BodyTextStyle}"
                                                           Margin="12,0"
                                                           VerticalAlignment="Center"/>
                                                <TextBlock x:Name="RemovableDriverCount" 
                                                           Text="0 removable" 
                                                           Style="{StaticResource BodyTextStyle}"
                                                           Foreground="{StaticResource AccentBrush}"
                                                           VerticalAlignment="Center"/>
                                                <TextBlock Text=" - " 
                                                           Style="{StaticResource BodyTextStyle}"
                                                           Margin="12,0"
                                                           VerticalAlignment="Center"/>
                                                <TextBlock x:Name="SelectedForRemovalCount" 
                                                           Text="0 selected for removal" 
                                                           Style="{StaticResource BodyTextStyle}"
                                                           Foreground="{StaticResource DangerBrush}"
                                                           VerticalAlignment="Center"/>
                                            </StackPanel>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                            </TabControl>
                        </StackPanel>
                    </Border>
                    
                    <!-- Enhanced Configuration Card -->
                    <Border Style="{StaticResource FluentCard}">
                        <StackPanel>
                            <Grid Margin="0,0,0,16">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0"
                                           Text="&#xE713;" 
                                           FontFamily="Segoe MDL2 Assets"
                                           FontSize="16" 
                                           Margin="0,0,8,0"
                                           VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="1"
                                           Text="Configuration" 
                                           Style="{StaticResource SectionHeaderStyle}"
                                           Margin="0"
                                           VerticalAlignment="Center"
                                           AutomationProperties.HeadingLevel="2"/>
                            </Grid>
                            
                            <TextBlock Text="Mount Directory" FontWeight="SemiBold" FontSize="16" Margin="0,0,0,8"/>
                            <TextBlock Text="Temporary directory for mounting WIM images during processing." 
                                       Style="{StaticResource BodyTextStyle}" 
                                       Margin="0,0,0,12"/>
                            <Grid Margin="0,0,0,20">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="MountDirTextBox" 
                                         Style="{StaticResource FluentTextBox}" 
                                         Text="C:\Temp\WIM_Mount"
                                         Margin="0,0,12,0"
                                         AutomationProperties.Name="Mount directory path"
                                         KeyboardNavigation.TabIndex="13"/>
                                <Button x:Name="BrowseMountButton" 
                                        Grid.Column="1" 
                                        Style="{StaticResource FluentSecondaryButton}" 
                                        MinWidth="100"
                                        AutomationProperties.Name="Browse for mount directory"
                                        KeyboardNavigation.TabIndex="14">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock FontFamily="Segoe MDL2 Assets" 
                                                   Text="&#xE8B7;" 
                                                   FontSize="12" 
                                                   Margin="0,0,5,0"
                                                   VerticalAlignment="Center"/>
                                        <TextBlock Text="Browse" VerticalAlignment="Center"/>
                                    </StackPanel>
                                </Button>
                            </Grid>
                            
                            <TextBlock Text="Driver Installation Options" FontWeight="SemiBold" FontSize="16" Margin="0,0,0,12"/>
                            <CheckBox x:Name="RecurseCheckBox" 
                                      Content="Search subfolders recursively for driver files" 
                                      IsChecked="True" 
                                      Style="{StaticResource FluentCheckBox}"
                                      Margin="0,0,0,12"
                                      KeyboardNavigation.TabIndex="15"/>
                            <StackPanel Orientation="Horizontal">
                                <CheckBox x:Name="ForceUnsignedCheckBox" 
                                          Style="{StaticResource FluentCheckBox}"
                                          KeyboardNavigation.TabIndex="16"/>
                                <StackPanel Margin="12,0,0,0">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="&#xE7BA;" 
                                                   FontFamily="Segoe MDL2 Assets"
                                                   Foreground="{StaticResource ErrorBrush}" 
                                                   Margin="0,0,6,0" 
                                                   VerticalAlignment="Center"/>
                                        <TextBlock Text="Force installation of unsigned drivers" 
                                                   FontSize="14" 
                                                   Foreground="{StaticResource ErrorBrush}"/>
                                    </StackPanel>
                                    <TextBlock Text="Security Risk: Only enable for trusted drivers" 
                                               FontSize="12" 
                                               Foreground="{StaticResource ErrorBrush}" 
                                               FontStyle="Italic" 
                                               Margin="0,4,0,0"/>
                                </StackPanel>
                            </StackPanel>
                        </StackPanel>
                    </Border>
                    
                    <!-- Enhanced Progress Card -->
                    <Border Style="{StaticResource FluentCard}">
                        <StackPanel>
                            <Grid Margin="0,0,0,16">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0"
                                           Text="&#xE9D9;" 
                                           FontFamily="Segoe MDL2 Assets"
                                           FontSize="16" 
                                           Margin="0,0,8,0"
                                           VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="1"
                                           Text="Progress" 
                                           Style="{StaticResource SectionHeaderStyle}"
                                           Margin="0"
                                           VerticalAlignment="Center"
                                           AutomationProperties.HeadingLevel="2"/>
                            </Grid>
                            
                            <Grid Margin="0,0,0,16">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock x:Name="ProgressTextBlock" 
                                           Text="Ready to start driver management operations..." 
                                           Style="{StaticResource BodyTextStyle}"/>
                                <TextBlock x:Name="ProgressPercentageBlock" 
                                           Grid.Column="1" 
                                           Text="0%" 
                                           FontWeight="SemiBold" 
                                           FontSize="14"
                                           Foreground="{StaticResource AccentBrush}"/>
                            </Grid>
                            <ProgressBar x:Name="MainProgressBar" 
                                         Style="{StaticResource FluentProgressBar}"
                                         Margin="0,0,0,20"/>
                            
                            <Expander Header="View Detailed Output" 
                                      IsExpanded="False" 
                                      Margin="0,8,0,0"
                                      Style="{StaticResource FluentExpanderStyle}">
                                <Border Background="#1E1E1E" 
                                        CornerRadius="6" 
                                        Padding="16"
                                        BorderThickness="1"
                                        BorderBrush="{StaticResource ControlBorderBrush}">
                                    <TextBox x:Name="LogTextBox" 
                                             Background="Transparent" 
                                             Foreground="#FFFFFF" 
                                             BorderThickness="0" 
                                             FontFamily="Consolas, 'Courier New'" 
                                             FontSize="12" 
                                             IsReadOnly="True" 
                                             VerticalScrollBarVisibility="Auto" 
                                             MinHeight="140"
                                             MaxHeight="280"
                                             TextWrapping="Wrap"
                                             AcceptsReturn="True"/>
                                </Border>
                            </Expander>
                        </StackPanel>
                    </Border>
                </StackPanel>
            </ScrollViewer>
        </Border>
    </Grid>
</Window>
"@

Write-Verbose "Enhanced Windows 11 Fluent Design XAML with driver management completed"
#endregion

#region 11. Enhanced UI Creation and Element Management
<#
.SYNOPSIS
    Creates and initializes the main application window and UI elements with driver management capabilities.
    
.DESCRIPTION
    This region handles complete UI initialization with enhanced visual features:
    - XAML parsing and window creation
    - UI element reference management with driver management controls
    - Accessibility configuration
    - Improved micro-interaction setup
    - Error handling for UI creation failures
#>

# Create main window from enhanced XAML with comprehensive error handling
try {
    Write-Verbose "Creating enhanced main application window with driver management from XAML definition..."
    
    # Validate the XAML string before parsing
    Write-Verbose "Enhanced XAML definition length: $($xamlDefinition.Length) characters"
    
    # Split XAML into lines for better error diagnostics
    $xamlLines = $xamlDefinition -split "`n"
    Write-Verbose "Enhanced XAML definition has $($xamlLines.Count) lines"
    
    # Use StringReader for more robust XAML parsing
    $stringReader = [System.IO.StringReader]::new($xamlDefinition)
    $xmlReader = [System.Xml.XmlReader]::Create($stringReader)
    $window = [System.Windows.Markup.XamlReader]::Load($xmlReader)
    $script:MainWindow = $window
    
    Write-Verbose "Enhanced main window with driver management created successfully"
}
catch [System.Xml.XmlException] {
    Write-Error "Enhanced XAML XML parsing failed at line $($_.Exception.LineNumber), position $($_.Exception.LinePosition): $($_.Exception.Message)"
    
    # Show problematic line content for debugging
    $xamlLines = $xamlDefinition -split "`n"
    if ($_.Exception.LineNumber -le $xamlLines.Count) {
        $problemLine = $xamlLines[$_.Exception.LineNumber - 1]
        Write-Error "Problematic line content: '$problemLine'"
        if ($_.Exception.LinePosition -le $problemLine.Length) {
            $beforeError = $problemLine.Substring(0, [Math]::Max(0, $_.Exception.LinePosition - 1))
            $afterError = if ($_.Exception.LinePosition -lt $problemLine.Length) { $problemLine.Substring($_.Exception.LinePosition - 1) } else { "" }
            Write-Error "Position context: '$beforeError' >>> ERROR HERE >>> '$afterError'"
        }
    }
    
    throw "Critical UI initialization failure due to XML parsing errors"
}
catch [System.Windows.Markup.XamlParseException] {
    Write-Error "Enhanced XAML markup parsing failed at line $($_.Exception.LineNumber), position $($_.Exception.LinePosition): $($_.Exception.Message)"
    throw "Critical UI initialization failure due to XAML markup errors"
}
catch {
    Write-Error "Unexpected error during enhanced window creation with driver management: $($_.Exception.Message)"
    Write-Error "Exception type: $($_.Exception.GetType().FullName)"
    throw "Critical UI initialization failure"
}
finally {
    # Ensure readers are properly disposed
    if ($xmlReader) { $xmlReader.Dispose() }
    if ($stringReader) { $stringReader.Dispose() }
}

# Initialize enhanced UI element references with comprehensive validation including driver management
try {
    Write-Verbose "Initializing enhanced UI element references with driver management..."
    
    # Define all UI elements that will be accessed by the application
    $uiElements = @{
        # File and folder selection controls
        WimFileTextBox           = $window.FindName("WimFileTextBox")
        DriverFolderTextBox      = $window.FindName("DriverFolderTextBox")
        MountDirTextBox          = $window.FindName("MountDirTextBox")
        
        # Action buttons
        BrowseWimButton          = $window.FindName("BrowseWimButton")
        BrowseDriverButton       = $window.FindName("BrowseDriverButton")
        BrowseMountButton        = $window.FindName("BrowseMountButton")
        ScanDriversButton        = $window.FindName("ScanDriversButton")
        StartButton              = $window.FindName("StartButton")
        CancelButton             = $window.FindName("CancelButton")
        
        # Driver management specific controls
        InventoryDriversButton   = $window.FindName("InventoryDriversButton")
        ExportDriversButton      = $window.FindName("ExportDriversButton")
        RemoveDriversButton      = $window.FindName("RemoveDriversButton")
        DriverManagementCard     = $window.FindName("DriverManagementCard")
        DriverTabControl         = $window.FindName("DriverTabControl")
        
        # Driver selection controls (Add Drivers tab)
        DriverPrereqHint         = $window.FindName("DriverPrereqHint")
        DriverSelectionCard      = $window.FindName("DriverSelectionCard")
        DriverListPanel          = $window.FindName("DriverListPanel")
        SelectAllDriversButton   = $window.FindName("SelectAllDriversButton")
        DeselectAllDriversButton = $window.FindName("DeselectAllDriversButton")
        DriverSummaryText        = $window.FindName("DriverSummaryText")
        SelectedDriverCount      = $window.FindName("SelectedDriverCount")
        UnsignedDriverWarning    = $window.FindName("UnsignedDriverWarning")
        
        # Installed drivers controls (Installed Drivers tab)
        InstalledDriverListPanel = $window.FindName("InstalledDriverListPanel")
        InstalledDriverCount     = $window.FindName("InstalledDriverCount")
        RemovableDriverCount     = $window.FindName("RemovableDriverCount")
        SelectedForRemovalCount  = $window.FindName("SelectedForRemovalCount")
        
        # Configuration controls
        RecurseCheckBox          = $window.FindName("RecurseCheckBox")
        ForceUnsignedCheckBox    = $window.FindName("ForceUnsignedCheckBox")
        
        # Progress and logging controls
        MainProgressBar          = $window.FindName("MainProgressBar")
        ProgressTextBlock        = $window.FindName("ProgressTextBlock")
        ProgressPercentageBlock  = $window.FindName("ProgressPercentageBlock")
        LogTextBox               = $window.FindName("LogTextBox")
        
        # Enhanced status and workflow indicators
        SecurityStatusBlock      = $window.FindName("SecurityStatusBlock")
        SecurityStatusContainer  = $window.FindName("SecurityStatusContainer")
        
        # Enhanced step indicators for better visual feedback
        Step1Indicator           = $window.FindName("Step1Indicator")
        Step2Indicator           = $window.FindName("Step2Indicator")
        Step3Indicator           = $window.FindName("Step3Indicator")
        Step4Indicator           = $window.FindName("Step4Indicator")
    }
    
    # Verify that all critical UI elements were found
    $criticalElements = @('StartButton', 'CancelButton', 'WimFileTextBox', 'DriverFolderTextBox', 'MainProgressBar', 'LogTextBox', 'InventoryDriversButton', 'DriverTabControl')
    $missingElements = @()
    
    foreach ($element in $criticalElements) {
        if (-not $uiElements[$element]) {
            $missingElements += $element
        }
    }
    
    if ($missingElements.Count -gt 0) {
        throw "Critical UI elements not found in enhanced XAML: $($missingElements -join ', ')"
    }
    
    Write-Verbose "All enhanced UI element references with driver management initialized successfully"
}
catch {
    Write-Error "Failed to initialize enhanced UI element references with driver management: $($_.Exception.Message)"
    throw "Enhanced UI element initialization failure"
}

# Configure enhanced accessibility properties for all controls including driver management
try {
    Write-Verbose "Configuring enhanced accessibility properties with driver management..."
    
    # Configure accessibility for primary action buttons
    Set-ControlAccessibility -Control $uiElements.StartButton -Name "Start driver management" -HelpText "Begin the driver management process with selected WIM file" -AcceleratorKey "Alt+Enter" -IsRequiredForForm $false
    Set-ControlAccessibility -Control $uiElements.CancelButton -Name "Cancel or exit" -HelpText "Cancel current operation or exit application" -AcceleratorKey "Escape"
    
    # Configure accessibility for file selection controls
    Set-ControlAccessibility -Control $uiElements.WimFileTextBox -Name "WIM file path" -HelpText "Path to Windows image file for modification" -IsRequiredForForm $true
    Set-ControlAccessibility -Control $uiElements.DriverFolderTextBox -Name "Driver folder path" -HelpText="Path to folder containing driver packages" -IsRequiredForForm $true
    Set-ControlAccessibility -Control $uiElements.MountDirTextBox -Name "Mount directory" -HelpText "Temporary directory for mounting operations"
    
    # Configure accessibility for browse buttons
    Set-ControlAccessibility -Control $uiElements.BrowseWimButton -Name "Browse for WIM file" -HelpText "Click to select a Windows image file" -AcceleratorKey "Alt+B"
    Set-ControlAccessibility -Control $uiElements.BrowseDriverButton -Name "Browse for driver folder" -HelpText "Click to select a folder containing driver packages" -AcceleratorKey "Alt+D"
    Set-ControlAccessibility -Control $uiElements.BrowseMountButton -Name "Browse for mount directory" -HelpText "Click to select a mount directory"
    Set-ControlAccessibility -Control $uiElements.ScanDriversButton -Name "Scan for drivers" -HelpText "Click to scan the selected folder for driver packages" -AcceleratorKey "Alt+S"
    
    # Configure accessibility for driver management controls
    Set-ControlAccessibility -Control $uiElements.InventoryDriversButton -Name "Inventory installed drivers" -HelpText "Click to scan and inventory drivers currently installed in the WIM file"
    Set-ControlAccessibility -Control $uiElements.ExportDriversButton -Name "Export selected drivers" -HelpText "Click to export selected drivers to a backup location"
    Set-ControlAccessibility -Control $uiElements.RemoveDriversButton -Name "Remove selected drivers" -HelpText "Click to remove selected drivers from the WIM file"
    
    # Configure accessibility for driver selection controls
    Set-ControlAccessibility -Control $uiElements.SelectAllDriversButton -Name "Select all drivers" -HelpText "Select all available drivers for injection"
    Set-ControlAccessibility -Control $uiElements.DeselectAllDriversButton -Name "Deselect all drivers" -HelpText "Deselect all drivers"
    
    # Configure accessibility for configuration controls
    Set-ControlAccessibility -Control $uiElements.RecurseCheckBox -Name "Search subfolders recursively" -HelpText "When enabled, searches all subfolders for driver files"
    Set-ControlAccessibility -Control $uiElements.ForceUnsignedCheckBox -Name "Force installation of unsigned drivers" -HelpText="WARNING: Enable this option to allow installation of unsigned drivers, which poses security risks"
    
    # Configure accessibility for progress controls
    Set-ControlAccessibility -Control $uiElements.MainProgressBar -Name "Operation progress" -HelpText "Shows progress of current operation"
    Set-ControlAccessibility -Control $uiElements.LogTextBox -Name "Operation log" -HelpText "Detailed log of operations and any errors"
    
    Write-Verbose "Enhanced accessibility properties with driver management configured successfully"
}
catch {
    Write-Warning "Failed to set some enhanced accessibility properties with driver management: $($_.Exception.Message)"
    # Continue execution as accessibility failures shouldn't stop the application
}

# Setup enhanced micro-interactions for better user experience including driver management buttons
try {
    Write-Verbose "Setting up enhanced micro-interactions for superior user experience with driver management..."
    
    # Define all buttons that should have enhanced micro-interactions
    $buttonsForAnimation = @(
        $uiElements.StartButton, $uiElements.CancelButton, 
        $uiElements.BrowseWimButton, $uiElements.BrowseDriverButton, $uiElements.BrowseMountButton, 
        $uiElements.ScanDriversButton, $uiElements.SelectAllDriversButton, $uiElements.DeselectAllDriversButton,
        $uiElements.InventoryDriversButton, $uiElements.ExportDriversButton, $uiElements.RemoveDriversButton
    )
    
    # Apply enhanced micro-interactions to each button
    foreach ($button in $buttonsForAnimation) {
        if ($button) {
            Add-ButtonMicroInteractions -Button $button -AnimationDurationMs 150
        }
        else {
            Write-Verbose "Skipping enhanced micro-interactions for null button reference"
        }
    }
    
    Write-Verbose "Enhanced micro-interactions with driver management configured for all buttons successfully"
}
catch {
    Write-Warning "Failed to setup some enhanced micro-interactions with driver management: $($_.Exception.Message)"
    # Continue execution as animation failures shouldn't stop the application
}

Write-Verbose "Enhanced UI creation and element management with driver management completed successfully"
#endregion

#region 12. Simplified Event Handlers
<#
.SYNOPSIS
    Enhanced event handlers for all UI interactions including driver management capabilities.
#>

# WIM File Browse Handler
$uiElements.BrowseWimButton.Add_Click({
        try {
            Write-Verbose "User initiated WIM file selection"
        
            $openFileDialog = [System.Windows.Forms.OpenFileDialog]::new()
            $openFileDialog.Filter = "Windows Image Files (*.wim)|*.wim|Extended WIM Files (*.esd)|*.esd|All Supported (*.wim;*.esd)|*.wim;*.esd"
            $openFileDialog.Title = "Select Windows Image File"
            $openFileDialog.CheckFileExists = $true
            $openFileDialog.CheckPathExists = $true
            $openFileDialog.Multiselect = $false
            $openFileDialog.RestoreDirectory = $true
        
            try {
                $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            }
            catch {
                Write-Verbose "Could not set initial directory to Desktop"
            }
        
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                Write-Verbose "User selected file: $($openFileDialog.FileName)"
            
                $validation = Test-WimFileValidation -WimPath $openFileDialog.FileName
                if ($validation.IsValid) {
                    $uiElements.WimFileTextBox.Text = $validation.ResolvedPath
                    $uiElements.InventoryDriversButton.IsEnabled = $true
                    $uiElements.DriverManagementCard.Visibility = [System.Windows.Visibility]::Visible
                    $uiElements.BrowseDriverButton.IsEnabled = $true
                    if ($uiElements.DriverPrereqHint) {
                        $uiElements.DriverPrereqHint.Visibility = [System.Windows.Visibility]::Collapsed
                    }
                
                    # Reset installed driver display
                    $uiElements.InstalledDriverListPanel.Children.Clear()
                    $noDriversText = [System.Windows.Controls.TextBlock]::new()
                    $noDriversText.Text = "Click 'Inventory Drivers' to scan for installed drivers in this WIM file."
                    $noDriversText.Style = $window.FindResource("BodyTextStyle")
                    $noDriversText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
                    $noDriversText.Margin = [System.Windows.Thickness]::new(20)
                    $noDriversText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(138, 136, 134))
                    $uiElements.InstalledDriverListPanel.Children.Add($noDriversText) | Out-Null
                
                    # Detect target image type and architecture so driver
                    # suitability can be judged for boot.wim vs install.wim.
                    $script:CurrentWimImageType = Get-WimImageType -WimFilePath $validation.ResolvedPath
                    $script:CurrentWimArchitecture = Get-WimArchitecture -WimFilePath $validation.ResolvedPath
                    $detectedType = $script:CurrentWimImageType.ToString()
                    Write-ApplicationLog "WIM file selected: $([System.IO.Path]::GetFileName($validation.ResolvedPath))" ([LogLevel]::Info)
                    Write-ApplicationLog "Detected image type: $detectedType (architecture: $($script:CurrentWimArchitecture))" ([LogLevel]::Info)
                    if ($script:CurrentWimImageType -eq [WimImageType]::Boot) {
                        Write-ApplicationLog "boot.wim target: only storage/network drivers will be recommended" ([LogLevel]::Info)
                    }
                    elseif ($script:CurrentWimImageType -eq [WimImageType]::Install) {
                        Write-ApplicationLog "install.wim target: all architecture-matched drivers are suitable" ([LogLevel]::Info)
                    }
                }
                else {
                    [System.Windows.MessageBox]::Show(
                        "WIM file validation failed:`n`n$($validation.ErrorMessage)", 
                        "Invalid WIM File", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Error
                    )
                    Write-ApplicationLog "WIM file validation failed: $($validation.ErrorMessage)" ([LogLevel]::Error)
                }
            }
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Unable to open file selection dialog: $($_.Exception.Message)", 
                "File Selection Error", 
                [System.Windows.MessageBoxButton]::OK, 
                [System.Windows.MessageBoxImage]::Error
            )
            Write-ApplicationLog "Error during WIM file selection: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            if ($openFileDialog) {
                $openFileDialog.Dispose()
            }
        }
    })

# Enhanced Driver Inventory Handler
$uiElements.InventoryDriversButton.Add_Click({
        # Prevent re-entry if an operation is already running
        if ($script:ApplicationState.IsProcessing()) {
            Write-ApplicationLog "An operation is already in progress. Please wait." ([LogLevel]::Warning)
            return
        }

        # Pre-flight Checks
        $wimPath = $uiElements.WimFileTextBox.Text
        if ([string]::IsNullOrWhiteSpace($wimPath) -or $wimPath -eq "No WIM file selected...") {
            [System.Windows.MessageBox]::Show("Please select a WIM file first.", "No WIM File", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $mountPath = $uiElements.MountDirTextBox.Text
        $mountPrereqValidation = Test-MountPathPrerequisites -MountPath $mountPath
        if (-not $mountPrereqValidation.IsValid) {
            [System.Windows.MessageBox]::Show("Invalid mount directory: $($mountPrereqValidation.ErrorMessage)", "Mount Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        # Get WIM Indexes and let user choose one
        try {
            $indexes = Get-WimIndexes -WimFilePath $wimPath
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to read WIM file indexes: $($_.Exception.Message)", "WIM Read Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        $selectedIndex = $indexes[0]
        if ($indexes.Count -gt 1) {
            $prompt = "This WIM contains multiple indexes ($($indexes -join ', ')).`nPlease enter the index number you want to inventory:"
            try {
                [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
                $inputValue = [Microsoft.VisualBasic.Interaction]::InputBox($prompt, "Select WIM Index", $indexes[0])
                if ([string]::IsNullOrWhiteSpace($inputValue)) {
                    Write-ApplicationLog "Driver inventory cancelled by user." ([LogLevel]::Info)
                    return
                }
                if ($indexes -contains [int]$inputValue) {
                    $selectedIndex = [int]$inputValue
                }
                else {
                    [System.Windows.MessageBox]::Show("Invalid index '$inputValue'. Aborting.", "Invalid Input", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    return
                }
            }
            catch {
                Write-ApplicationLog "Could not show index selection prompt. Defaulting to first index. Error: $($_.Exception.Message)" ([LogLevel]::Warning)
            }
        }

        # Show warning for potentially long operation
        $wimFileInfo = [System.IO.FileInfo]::new($wimPath)
        $wimSizeGB = [math]::Round($wimFileInfo.Length / 1GB, 1)
    
        if ($wimSizeGB -gt 2) {
            $result = [System.Windows.MessageBox]::Show(
                "LARGE WIM FILE DETECTED ($wimSizeGB GB)`n`nMounting large WIM files can take 10-30 minutes or more.`n`nOperation details will be shown in the log below.`nYou can cancel at any time using the Cancel button.`n`nProceed with driver inventory?", 
                "Large File Warning", 
                [System.Windows.MessageBoxButton]::YesNo, 
                [System.Windows.MessageBoxImage]::Information
            )
            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                return
            }
        }

        # Update UI for Long Operation
        $script:ApplicationState.SetCurrentState('InventoryingDrivers')
        $uiElements.InventoryDriversButton.IsEnabled = $false
        $uiElements.BrowseWimButton.IsEnabled = $false
        $uiElements.StartButton.IsEnabled = $false
        $uiElements.InventoryDriversButton.Content = "Scanning..."
        $uiElements.CancelButton.Content = "Cancel Inventory"
        $uiElements.CancelButton.IsEnabled = $true
        $uiElements.MainProgressBar.IsIndeterminate = $false
        $uiElements.MainProgressBar.Value = 0
        $uiElements.InstalledDriverListPanel.Children.Clear()
    
        Write-ApplicationLog "Starting driver inventory for WIM: $([System.IO.Path]::GetFileName($wimPath)) (Index: $selectedIndex, Size: $wimSizeGB GB)" ([LogLevel]::Info)
        Write-ApplicationLog "This operation may take 10-30 minutes for large files. Please be patient." ([LogLevel]::Info)

        # Create PowerShell Runspace for Real-time Output
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $runspace.Open()
    
        # Pass variables and functions to runspace
        $runspace.SessionStateProxy.SetVariable("WimFilePath", $wimPath)
        $runspace.SessionStateProxy.SetVariable("MountDirectory", $mountPath)
        $runspace.SessionStateProxy.SetVariable("WimIndex", $selectedIndex)
        $runspace.SessionStateProxy.SetVariable("WimSizeGB", $wimSizeGB)
        $runspace.SessionStateProxy.SetVariable("Configuration", $script:Configuration)

        $powershell = [System.Management.Automation.PowerShell]::Create()
        $powershell.Runspace = $runspace
    
        # Store references for cancellation
        $script:ApplicationState.SetCurrentPowerShell($powershell)
        $script:ApplicationState.SetCurrentRunspace($runspace)

        # FIXED Real-time Inventory Script
        $inventoryScript = {
            $result = @{ Success = $false; Drivers = @(); ErrorMessage = ""; Progress = 0 }
    
            try {
                # Create event for progress updates
                $progressEvent = "InventoryProgress"
        
                function Send-Progress {
                    param($Percentage, $Status, $Detail = "")
                    Register-EngineEvent -SourceIdentifier $progressEvent -MessageData @{
                        Progress = $Percentage
                        Status   = $Status  
                        Detail   = $Detail
                    } | Out-Null
                }
        
                function Send-Log {
                    param($Message, $Level = "Info")
                    Register-EngineEvent -SourceIdentifier "InventoryLog" -MessageData @{
                        Message = $Message
                        Level   = $Level
                    } | Out-Null
                }

                # Helper function to execute DISM with proper arguments
                function Invoke-DismCommand {
                    param(
                        [string]$Operation,
                        [hashtable]$Arguments,
                        [int]$TimeoutMs = 300000
                    )
            
                    # Build argument list properly
                    $argumentList = [System.Collections.Generic.List[string]]::new()
                    $argumentList.Add($Operation)
            
                    foreach ($key in $Arguments.Keys) {
                        $value = $Arguments[$key]
                
                        switch ($key) {
                            'ImageFile' { $argumentList.Add("/ImageFile:`"$value`"") }
                            'WimFile' { $argumentList.Add("/WimFile:`"$value`"") }
                            'Image' { $argumentList.Add("/Image:`"$value`"") }
                            'MountDir' { $argumentList.Add("/MountDir:`"$value`"") }
                            'Index' { $argumentList.Add("/Index:$value") }
                            'All' { if ([bool]$value) { $argumentList.Add("/All") } }
                            'Commit' { if ([bool]$value) { $argumentList.Add("/Commit") } }
                            'Discard' { if ([bool]$value) { $argumentList.Add("/Discard") } }
                        }
                    }
            
                    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
                    $processInfo.FileName = "dism.exe"
                    $processInfo.Arguments = $argumentList -join ' '
                    $processInfo.UseShellExecute = $false
                    $processInfo.CreateNoWindow = $true
                    $processInfo.RedirectStandardOutput = $true
                    $processInfo.RedirectStandardError = $true
            
                    $process = [System.Diagnostics.Process]::Start($processInfo)
            
                    $outputTask = $process.StandardOutput.ReadToEndAsync()
                    $errorTask = $process.StandardError.ReadToEndAsync()

                    if (-not $process.WaitForExit($TimeoutMs)) {
                        try {
                            $process.Kill()
                            $process.WaitForExit(5000)
                        }
                        catch { }
                        throw "Operation timed out after $($TimeoutMs / 1000) seconds"
                    }
            
                    $output = $outputTask.Result
                    $errorOutput = $errorTask.Result
                    $exitCode = $process.ExitCode
                    $process.Dispose()
            
                    return @{
                        Success  = ($exitCode -eq 0)
                        ExitCode = $exitCode
                        Output   = $output
                        Error    = $errorOutput
                    }
                }

                Send-Log "Starting driver inventory operation..." "Info"
                Send-Progress 5 "Preparing mount directory..."

                # Clear mount directory
                Send-Log "Clearing mount directory: $MountDirectory" "Info"
                if ([System.IO.Directory]::Exists($MountDirectory)) {
                    Send-Log "Cleaning up existing mount directory..." "Info"
            
                    # Try unmount first
                    try {
                        $unmountResult = Invoke-DismCommand -Operation "/Unmount-Image" -Arguments @{
                            MountDir = $MountDirectory
                            Discard  = $true
                        } -TimeoutMs 60000
                
                        if ($unmountResult.Success) {
                            Send-Log "Successfully unmounted existing mount." "Success"
                        }
                        else {
                            Send-Log "Unmount attempt completed (may not have been mounted)." "Info"
                        }
                    }
                    catch {
                        Send-Log "Unmount attempt: $($_.Exception.Message)" "Info"
                    }
            
                    # Global cleanup
                    try {
                        Send-Log "Running global DISM cleanup..." "Info"
                        $cleanupProcess = Start-Process "dism.exe" -ArgumentList "/Cleanup-Mountpoints" -Wait -PassThru -NoNewWindow
                        Send-Log "Global cleanup completed with exit code: $($cleanupProcess.ExitCode)" "Info"
                    }
                    catch {
                        Send-Log "Global cleanup error: $($_.Exception.Message)" "Warning"
                    }
            
                    # Remove directory
                    if ([System.IO.Directory]::Exists($MountDirectory)) {
                        Start-Sleep -Seconds 2
                        try {
                            Remove-Item -Path $MountDirectory -Recurse -Force -ErrorAction Stop
                            Send-Log "Mount directory removed successfully." "Success"
                        }
                        catch {
                            Send-Log "Could not remove mount directory: $($_.Exception.Message)" "Warning"
                        }
                    }
                }

                # Create fresh mount directory
                [System.IO.Directory]::CreateDirectory($MountDirectory) | Out-Null
                Send-Log "Created clean mount directory." "Success"
                Send-Progress 10 "Mount directory prepared"

                # Mount WIM with proper error handling
                Send-Progress 15 "Mounting WIM index $WimIndex (this will take several minutes for large files)..."
                Send-Log "Starting DISM mount operation for index $WimIndex..." "Info"
                Send-Log "Expected time: 5-25 minutes depending on WIM size ($WimSizeGB GB)" "Info"
        
                $mountResult = Invoke-DismCommand -Operation "/Mount-Image" -Arguments @{
                    ImageFile = $WimFilePath
                    Index     = $WimIndex
                    MountDir  = $MountDirectory
                } -TimeoutMs 1800000  # 30 minutes
        
                if (-not $mountResult.Success) {
                    Send-Log "Mount failed with exit code: $($mountResult.ExitCode)" "Error"
                    if ($mountResult.Error) {
                        Send-Log "DISM Error: $($mountResult.Error)" "Error"
                    }
                    throw "Failed to mount WIM index $WimIndex"
                }
        
                Send-Log "Mount completed successfully" "Success"
        
                # Verify mount
                $windowsPath = [System.IO.Path]::Combine($MountDirectory, "Windows")
                if (-not [System.IO.Directory]::Exists($windowsPath)) {
                    throw "Mount verification failed - Windows directory not found in mounted image"
                }
                Send-Log "Mount verification successful." "Success"
        
                # Start driver inventory with FIXED command
                Send-Progress 80 "Scanning for installed drivers..."
                Send-Log "Starting driver inventory scan..." "Info"
        
                # Use proper /Get-Drivers syntax
                $driverResult = Invoke-DismCommand -Operation "/Get-Drivers" -Arguments @{
                    Image = $MountDirectory
                } -TimeoutMs 300000  # 5 minutes
        
                if (-not $driverResult.Success) {
                    Send-Log "Driver scan failed with exit code: $($driverResult.ExitCode)" "Error"
                    Send-Log "DISM Error: $($driverResult.Error)" "Error"
                    throw "Driver inventory failed"
                }
        
                Send-Progress 90 "Parsing driver information..."
                Send-Log "Driver scan completed, parsing results..." "Success"
        
                # Parse driver output
                $drivers = [System.Collections.Generic.List[object]]::new()
                $driverOutput = $driverResult.Output
        
                if ([string]::IsNullOrWhiteSpace($driverOutput)) {
                    Send-Log "No driver output received from DISM" "Warning"
                }
                else {
                    # Parse the output
                    $lines = $driverOutput -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            
                    $currentDriver = $null
                    foreach ($line in $lines) {
                        if ($line -match "Published Name\s*:\s*(.+)") {
                            if ($currentDriver) {
                                $drivers.Add($currentDriver)
                            }
                            $currentDriver = @{
                                PublishedName    = $matches[1].Trim()
                                OriginalFileName = "Unknown"
                                ClassName        = "Unknown"
                                ProviderName     = "Unknown"
                                DriverDate       = "Unknown"
                                DriverVersion    = "Unknown"
                                InboxDriver      = $false
                            }
                        }
                        elseif ($currentDriver) {
                            if ($line -match "Original File Name\s*:\s*(.+)") {
                                $currentDriver.OriginalFileName = $matches[1].Trim()
                            }
                            elseif ($line -match "Class Name\s*:\s*(.+)") {
                                $currentDriver.ClassName = $matches[1].Trim()
                            }
                            elseif ($line -match "Provider Name\s*:\s*(.+)") {
                                $currentDriver.ProviderName = $matches[1].Trim()
                            }
                            elseif ($line -match "Date\s*:\s*(.+)") {
                                $currentDriver.DriverDate = $matches[1].Trim()
                            }
                            elseif ($line -match "Version\s*:\s*(.+)") {
                                $currentDriver.DriverVersion = $matches[1].Trim()
                            }
                            elseif ($line -match "Inbox\s*:\s*(.+)") {
                                $currentDriver.InboxDriver = ($matches[1].Trim() -eq "Yes")
                            }
                        }
                    }
            
                    # Add the last driver if exists
                    if ($currentDriver) {
                        $drivers.Add($currentDriver)
                    }
            
                    # Convert to PSObject
                    $result.Drivers = $drivers | ForEach-Object { New-Object PSObject -Property $_ }
                }
        
                $result.Success = $true
                Send-Log "Found $($drivers.Count) installed drivers" "Success"
                Send-Progress 95 "Preparing to unmount..."
        
            }
            catch {
                $result.ErrorMessage = $_.Exception.Message
                Send-Log "Error during driver inventory: $($_.Exception.Message)" "Error"
            }
            finally {
                # Always try to unmount
                Send-Progress 98 "Unmounting WIM image..."
                Send-Log "Starting unmount operation..." "Info"
        
                try {
                    # Use the helper function for unmount
                    $unmountResult = Invoke-DismCommand -Operation "/Unmount-Image" -Arguments @{
                        MountDir = $MountDirectory
                        Discard  = $true
                    } -TimeoutMs 180000
            
                    if ($unmountResult.Success) {
                        Send-Log "Image unmounted successfully." "Success"
                    }
                    else {
                        Send-Log "Unmount completed with exit code: $($unmountResult.ExitCode)" "Warning"
                    }
                }
                catch {
                    Send-Log "Error during unmount: $($_.Exception.Message)" "Error"
                }
        
                Send-Progress 100 "Operation completed"
            }
    
            return $result
        }
    
        $powershell.AddScript($inventoryScript)
    
        # Start Background Operation
        $asyncResult = $powershell.BeginInvoke()
        $script:ApplicationState.SetBackgroundResult($asyncResult)
    
        # Set up Event Monitoring
        $progressSubscription = Register-EngineEvent -SourceIdentifier "InventoryProgress" -Action {
            $eventData = $Event.MessageData
            Update-ApplicationProgress $eventData.Progress $eventData.Status
            if (-not [string]::IsNullOrWhiteSpace($eventData.Detail)) {
                Write-ApplicationLog $eventData.Detail ([LogLevel]::Info)
            }
        }
    
        $logSubscription = Register-EngineEvent -SourceIdentifier "InventoryLog" -Action {
            $eventData = $Event.MessageData
            Write-ApplicationLog $eventData.Message $eventData.Level
        }
    
        # Monitor Operation with UI Updates
        $monitorTimer = [System.Windows.Threading.DispatcherTimer]::new()
        $monitorTimer.Interval = [TimeSpan]::FromMilliseconds(1000)
    
        # This is the corrected monitoring timer section (starting around line 400)
        $monitorTimer.Add_Tick({
                if ($asyncResult.IsCompleted) {
                    $monitorTimer.Stop()
        
                    try {
                        # Get results
                        $jobResult = $powershell.EndInvoke($asyncResult)
            
                        if ($jobResult.Success) {
                            Write-ApplicationLog "Driver inventory completed successfully. Found $($jobResult.Drivers.Count) drivers." ([LogLevel]::Success)
                            Update-ApplicationProgress 100 "Inventory complete. Found $($jobResult.Drivers.Count) drivers."
                
                            # Update application state and UI
                            $script:ApplicationState.InstalledDrivers.Clear()
                            foreach ($driver in $jobResult.Drivers) {
                                # Convert PSObject to InstalledDriverInfo properly
                                $driverProperties = @{}
                                foreach ($prop in $driver.psobject.Properties) {
                                    $driverProperties[$prop.Name] = $prop.Value
                                }
                                $driverInfo = [InstalledDriverInfo]::new($driverProperties)
                                [void]$script:ApplicationState.InstalledDrivers.Add($driverInfo)
                            }
                            Update-InstalledDriverUI -Drivers $script:ApplicationState.InstalledDrivers.ToArray()
                        }
                        else {
                            Write-ApplicationLog "Driver inventory failed: $($jobResult.ErrorMessage)" ([LogLevel]::Error)
                            Update-ApplicationProgress 0 "Inventory failed."
                            [System.Windows.MessageBox]::Show("Driver inventory failed: $($jobResult.ErrorMessage)", "Inventory Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                        }
                    }
                    catch {
                        Write-ApplicationLog "Error processing inventory results: $($_.Exception.Message)" ([LogLevel]::Error)
                        Update-ApplicationProgress 0 "Inventory failed with exception."
                        [System.Windows.MessageBox]::Show("Error processing inventory results: $($_.Exception.Message)", "Processing Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    }
                    finally {
                        # Cleanup
                        try {
                            if ($progressSubscription) {
                                Unregister-Event -SubscriptionId $progressSubscription.Id -ErrorAction SilentlyContinue
                            }
                            if ($logSubscription) {
                                Unregister-Event -SubscriptionId $logSubscription.Id -ErrorAction SilentlyContinue
                            }
                            $powershell.Dispose()
                            $runspace.Close()
                            $runspace.Dispose()
                        }
                        catch { 
                            Write-Verbose "Cleanup error: $($_.Exception.Message)"
                        }
            
                        # Reset UI
                        $uiElements.MainProgressBar.Value = 0
                        $uiElements.InventoryDriversButton.IsEnabled = $true
                        $uiElements.BrowseWimButton.IsEnabled = $true
                        $uiElements.StartButton.IsEnabled = $true
                        $uiElements.InventoryDriversButton.Content = "Inventory Drivers"
                        $uiElements.CancelButton.Content = "Cancel"
                        $script:ApplicationState.SetCurrentState('Idle')
                        $script:ApplicationState.SetCurrentPowerShell($null)
                        $script:ApplicationState.SetCurrentRunspace($null)
                        $script:ApplicationState.SetBackgroundResult($null)
                    }
                }
                elseif ($script:ApplicationState.GetCurrentState() -eq 'Cancelling') {
                    # Handle cancellation
                    $monitorTimer.Stop()
                    Write-ApplicationLog "Cancelling driver inventory operation..." ([LogLevel]::Warning)
        
                    try {
                        $powershell.Stop()
                        Start-Sleep -Seconds 2
            
                        # Force cleanup
                        try {
                            Start-Process "dism.exe" -ArgumentList "/Cleanup-Mountpoints" -Wait -NoNewWindow -WindowStyle Hidden
                        }
                        catch { 
                            Write-Verbose "Cleanup error: $($_.Exception.Message)"
                        }
            
                        Write-ApplicationLog "Driver inventory operation cancelled by user." ([LogLevel]::Warning)
                    }
                    catch {
                        Write-ApplicationLog "Error during cancellation: $($_.Exception.Message)" ([LogLevel]::Error)
                    }
                    finally {
                        # Cleanup
                        try {
                            if ($progressSubscription) {
                                Unregister-Event -SubscriptionId $progressSubscription.Id -ErrorAction SilentlyContinue
                            }
                            if ($logSubscription) {
                                Unregister-Event -SubscriptionId $logSubscription.Id -ErrorAction SilentlyContinue
                            }
                            $powershell.Dispose()
                            $runspace.Close()
                            $runspace.Dispose()
                        }
                        catch { 
                            Write-Verbose "Cleanup error: $($_.Exception.Message)"
                        }
            
                        # Reset UI
                        Update-ApplicationProgress 0 "Operation cancelled"
                        $uiElements.MainProgressBar.Value = 0
                        $uiElements.InventoryDriversButton.IsEnabled = $true
                        $uiElements.BrowseWimButton.IsEnabled = $true
                        $uiElements.StartButton.IsEnabled = $true
                        $uiElements.InventoryDriversButton.Content = "Inventory Drivers"
                        $uiElements.CancelButton.Content = "Cancel"
                        $script:ApplicationState.SetCurrentState('Idle')
                        $script:ApplicationState.SetCurrentPowerShell($null)
                        $script:ApplicationState.SetCurrentRunspace($null)
                        $script:ApplicationState.SetBackgroundResult($null)
                    }
                }
            })

        $monitorTimer.Start()
    })

# Enhanced Driver Removal Handler
$uiElements.RemoveDriversButton.Add_Click({
        if ($script:ApplicationState.IsProcessing()) { return }

        try {
            Write-Verbose "User initiated driver removal operation"
        
            $mountPrereqValidation = Test-MountPathPrerequisites -MountPath $uiElements.MountDirTextBox.Text
            if (-not $mountPrereqValidation.IsValid) {
                [System.Windows.MessageBox]::Show(
                    "The selected mount directory does not meet the requirements for DISM operations:`n`n$($mountPrereqValidation.ErrorMessage)",
                    "Invalid Mount Directory",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                )
                Write-ApplicationLog "Mount path prerequisite check failed: $($mountPrereqValidation.ErrorMessage)" ([LogLevel]::Error)
                return
            }

            $selectedDrivers = Get-SelectedInstalledDrivers
            if ($selectedDrivers.Count -eq 0) {
                [System.Windows.MessageBox]::Show(
                    "Please select at least one driver to remove.", 
                    "No Drivers Selected", 
                    [System.Windows.MessageBoxButton]::OK, 
                    [System.Windows.MessageBoxImage]::Information
                )
                return
            }
        
            $confirmMessage = "Are you sure you want to remove $($selectedDrivers.Count) driver(s)? This action cannot be undone and may affect system stability."
        
            $result = [System.Windows.MessageBox]::Show($confirmMessage, "Confirm Driver Removal", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
            if ($result -eq [System.Windows.MessageBoxResult]::No) { return }
        
            $uiElements.RemoveDriversButton.IsEnabled = $false
            $uiElements.ExportDriversButton.IsEnabled = $false
            $uiElements.ProgressTextBlock.Text = "Removing selected drivers..."
            $uiElements.MainProgressBar.IsIndeterminate = $true
            $script:ApplicationState.SetCurrentState('RemovingDrivers')
        
            Write-ApplicationLog "Starting driver removal for $($selectedDrivers.Count) drivers" ([LogLevel]::Info)
        
            $removalStartTime = Get-Date
            $indexes = Get-WimIndexes -WimFilePath $uiElements.WimFileTextBox.Text
            $mountPath = $uiElements.MountDirTextBox.Text
        
            $totalSuccessfulRemovals = 0
            $totalFailedRemovals = 0
        
            foreach ($index in $indexes) {
                try {
                    Write-ApplicationLog "Processing driver removal for index $index..." ([LogLevel]::Info)
                    Update-ApplicationProgress (($index / $indexes.Count) * 90) "Removing drivers from index $index..."
                
                    if (-not (Clear-MountDirectory -MountPath $mountPath)) {
                        Write-ApplicationLog "Failed to prepare mount directory for index $index" ([LogLevel]::Warning)
                        continue
                    }
                
                    $mountArgs = @{ ImageFile = $uiElements.WimFileTextBox.Text; Index = $index; MountDir = $mountPath }
                
                    $mountResult = Invoke-EnhancedDismOperation -Operation "/Mount-Image" -Arguments $mountArgs -TimeoutMs 1200000
                    if (-not $mountResult.Success) {
                        Write-ApplicationLog "Failed to mount index $index for driver removal" ([LogLevel]::Warning)
                        continue
                    }
                
                    Start-Sleep -Milliseconds 3000
                
                    $removalResult = Remove-DriversFromMountedImage -MountPath $mountPath -DriversToRemove $selectedDrivers -Force:$false
                
                    $totalSuccessfulRemovals += $removalResult.SuccessfulRemovals
                    $totalFailedRemovals += $removalResult.FailedRemovals

                    # --- CORRECTED UNMOUNT CALL ---
                    $unmountArgs = @{ MountDir = $mountPath; Commit = $true }
                    $unmountResult = Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $unmountArgs -TimeoutMs 180000
                
                    if ($unmountResult.Success) {
                        Write-ApplicationLog "Index ${index} successfully processed. Removed $($removalResult.SuccessfulRemovals) drivers." ([LogLevel]::Success)
                    }
                    else {
                        Write-ApplicationLog "Index ${index} failed to commit changes." ([LogLevel]::Error)
                    }
                }
                catch {
                    Write-ApplicationLog "Error processing driver removal for index ${index}: $($_.Exception.Message)" ([LogLevel]::Error)
                    try {
                        $emergencyArgs = @{ MountDir = $mountPath; Discard = $true }
                        Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $emergencyArgs | Out-Null
                    }
                    catch { }
                }
            }
        
            $removalDuration = (Get-Date) - $removalStartTime
            $successMessage = "Driver removal completed. Successfully removed: $totalSuccessfulRemovals drivers. Failed: $totalFailedRemovals drivers. Duration: $([math]::Round($removalDuration.TotalMinutes, 1)) minutes."
            Update-ApplicationProgress 100.0 $successMessage
            [System.Windows.MessageBox]::Show($successMessage, "Driver Removal Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Write-ApplicationLog $successMessage ([LogLevel]::Success)
        }
        catch {
            [System.Windows.MessageBox]::Show("Driver removal operation failed: $($_.Exception.Message)", "Driver Removal Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            Write-ApplicationLog "Driver removal operation failed: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            $uiElements.MainProgressBar.IsIndeterminate = $false
            $uiElements.MainProgressBar.Value = 0
            $uiElements.RemoveDriversButton.IsEnabled = $true
            $uiElements.ExportDriversButton.IsEnabled = $true
            $script:ApplicationState.SetCurrentState('Idle')
        }
    })

# Enhanced Driver Export Handler
$uiElements.ExportDriversButton.Add_Click({
        if ($script:ApplicationState.IsProcessing()) { return }
    
        try {
            Write-Verbose "User initiated driver export operation"
        
            $mountPrereqValidation = Test-MountPathPrerequisites -MountPath $uiElements.MountDirTextBox.Text
            if (-not $mountPrereqValidation.IsValid) {
                [System.Windows.MessageBox]::Show("Invalid mount directory: $($mountPrereqValidation.ErrorMessage)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                return
            }

            $folderDialog = [System.Windows.Forms.FolderBrowserDialog]::new()
            $folderDialog.Description = "Select destination folder for driver export"
            $folderDialog.ShowNewFolderButton = $true
        
            if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                Write-ApplicationLog "Starting driver export to: $($folderDialog.SelectedPath)" ([LogLevel]::Info)
            
                $uiElements.ExportDriversButton.IsEnabled = $false
                $uiElements.RemoveDriversButton.IsEnabled = $false
                $uiElements.ProgressTextBlock.Text = "Exporting drivers..."
                $uiElements.MainProgressBar.IsIndeterminate = $true
            
                $indexes = Get-WimIndexes -WimFilePath $uiElements.WimFileTextBox.Text
                $mountPath = $uiElements.MountDirTextBox.Text
            
                try {
                    if (-not (Clear-MountDirectory -MountPath $mountPath)) { throw "Failed to prepare mount directory" }
                
                    $mountArgs = @{ ImageFile = $uiElements.WimFileTextBox.Text; Index = $indexes[0]; MountDir = $mountPath }
                
                    # --- CORRECTED TIMEOUT ---
                    $mountResult = Invoke-EnhancedDismOperation -Operation "/Mount-Image" -Arguments $mountArgs -TimeoutMs 1200000 # 20 minutes
                    if (-not $mountResult.Success) { throw "Failed to mount WIM for driver export" }
                
                    Start-Sleep -Milliseconds 3000
                
                    $exportResult = Export-DriversFromMountedImage -MountPath $mountPath -DestinationPath $folderDialog.SelectedPath
                
                    $unmountArgs = @{ MountDir = $mountPath; Discard = $true }
                    Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $unmountArgs -TimeoutMs 120000 | Out-Null
                
                    if ($exportResult.Success) {
                        Update-ApplicationProgress 100.0 "Driver export completed successfully"
                        [System.Windows.MessageBox]::Show("Drivers exported successfully to:`n$($folderDialog.SelectedPath)", "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                        Write-ApplicationLog "Driver export completed successfully" ([LogLevel]::Success)
                    }
                    else {
                        throw $exportResult.ErrorMessage
                    }
                }
                catch {
                    [System.Windows.MessageBox]::Show("Driver export failed: $($_.Exception.Message)", "Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
                    Write-ApplicationLog "Driver export failed: $($_.Exception.Message)" ([LogLevel]::Error)
                }
                finally {
                    $uiElements.MainProgressBar.IsIndeterminate = $false
                    $uiElements.MainProgressBar.Value = 0
                    $uiElements.ExportDriversButton.IsEnabled = $true
                    $uiElements.RemoveDriversButton.IsEnabled = $true
                }
            }
        }
        catch {
            Write-ApplicationLog "Error during driver export: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            if ($folderDialog) { $folderDialog.Dispose() }
        }
    })

# Driver Folder Browse Handler
$uiElements.BrowseDriverButton.Add_Click({
        try {
            Write-Verbose "User initiated driver folder selection"
        
            $folderDialog = [System.Windows.Forms.FolderBrowserDialog]::new()
            $folderDialog.Description = "Select folder containing driver files (.inf)"
            $folderDialog.ShowNewFolderButton = $false
            $folderDialog.RootFolder = [System.Environment+SpecialFolder]::MyComputer
        
            if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                Write-Verbose "User selected folder: $($folderDialog.SelectedPath)"
            
                $validation = Test-DriverFolderValidation -DriverPath $folderDialog.SelectedPath
                if ($validation.IsValid) {
                    $uiElements.DriverFolderTextBox.Text = $validation.ResolvedPath
                    $uiElements.ScanDriversButton.IsEnabled = $true
                
                    $uiElements.DriverSelectionCard.Visibility = [System.Windows.Visibility]::Collapsed
                    $script:ApplicationState.DiscoveredDrivers.Clear()
                
                    Write-ApplicationLog "Driver folder selected: $([System.IO.Path]::GetFileName($validation.ResolvedPath)) ($($validation.AdditionalData.InfCount) INF files found)" ([LogLevel]::Info)
                }
                else {
                    [System.Windows.MessageBox]::Show(
                        "Driver folder validation failed:`n`n$($validation.ErrorMessage)", 
                        "Invalid Driver Folder", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Error
                    )
                    Write-ApplicationLog "Driver folder validation failed: $($validation.ErrorMessage)" ([LogLevel]::Error)
                }
            }
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Unable to open folder selection dialog: $($_.Exception.Message)", 
                "Folder Selection Error", 
                [System.Windows.MessageBoxButton]::OK, 
                [System.Windows.MessageBoxImage]::Error
            )
            Write-ApplicationLog "Error during driver folder selection: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            if ($folderDialog) {
                $folderDialog.Dispose()
            }
        }
    })

# Mount Directory Browse Handler
$uiElements.BrowseMountButton.Add_Click({
        try {
            Write-Verbose "User initiated mount directory selection"
    
            $folderDialog = [System.Windows.Forms.FolderBrowserDialog]::new()
            $folderDialog.Description = "Select a temporary directory for mounting WIMs. It should be on a local NTFS drive."
            $folderDialog.ShowNewFolderButton = $true
            # Start browsing from the root of the system drive for clarity
            $folderDialog.SelectedPath = $env:SystemDrive + "\"
    
            if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $selectedPath = $folderDialog.SelectedPath
                Write-Verbose "User selected mount directory: $selectedPath"
        
                # Validate the selected path for both security and DISM prerequisites
                $pathValidation = Test-SecurePath -Path $selectedPath
                if (-not $pathValidation.IsValid) {
                    [System.Windows.MessageBox]::Show(
                        "The selected mount directory path is not secure:`n`n$($pathValidation.ErrorMessage)", 
                        "Invalid Mount Directory", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Error
                    )
                    Write-ApplicationLog "Mount directory security validation failed: $($pathValidation.ErrorMessage)" ([LogLevel]::Error)
                    return
                }

                $prereqValidation = Test-MountPathPrerequisites -MountPath $pathValidation.ResolvedPath
                if (-not $prereqValidation.IsValid) {
                    [System.Windows.MessageBox]::Show(
                        "The selected mount directory does not meet DISM's requirements:`n`n$($prereqValidation.ErrorMessage)", 
                        "Invalid Mount Directory", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Error
                    )
                    Write-ApplicationLog "Mount directory prerequisite check failed: $($prereqValidation.ErrorMessage)" ([LogLevel]::Error)
                    return
                }
            
                # --- THIS IS THE FIX ---
                # The original code hard-coded the path here. This now correctly uses the user's selection.
                $uiElements.MountDirTextBox.Text = $prereqValidation.ResolvedPath
                Write-ApplicationLog "Mount directory updated to: $($prereqValidation.ResolvedPath)" ([LogLevel]::Info)
            }
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Unable to open directory selection dialog: $($_.Exception.Message)", 
                "Directory Selection Error", 
                [System.Windows.MessageBoxButton]::OK, 
                [System.Windows.MessageBoxImage]::Error
            )
            Write-ApplicationLog "Error during mount directory selection: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            if ($folderDialog) {
                $folderDialog.Dispose()
            }
        }
    })

# Updated Driver Scanning Handler - Using Enhanced Approach
$uiElements.ScanDriversButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($uiElements.DriverFolderTextBox.Text) -or 
            $uiElements.DriverFolderTextBox.Text -eq "No folder selected...") {
            [System.Windows.MessageBox]::Show(
                "Please select a driver folder first before scanning for drivers.", 
                "No Folder Selected", 
                [System.Windows.MessageBoxButton]::OK, 
                [System.Windows.MessageBoxImage]::Warning
            )
            return
        }
    
        try {
            Write-Verbose "Starting enhanced driver scanning operation"
        
            $uiElements.ScanDriversButton.IsEnabled = $false
            $uiElements.ScanDriversButton.Content = "Scanning..."
            $uiElements.ProgressTextBlock.Text = "Scanning for drivers..."
            $uiElements.MainProgressBar.IsIndeterminate = $true
            $script:ApplicationState.SetCurrentState('Scanning')
        
            Write-ApplicationLog "Starting enhanced driver scan in: $($uiElements.DriverFolderTextBox.Text)" ([LogLevel]::Info)
        
            $scanStartTime = Get-Date
        
            try {
                # Use the enhanced recursive driver discovery
                $drivers = Get-DriversRecursive -RootPath $uiElements.DriverFolderTextBox.Text
            
                # Clear and update discovered drivers list
                $script:ApplicationState.DiscoveredDrivers.Clear()
                foreach ($driver in $drivers) {
                    [void]$script:ApplicationState.DiscoveredDrivers.Add($driver)
                }
            
                # Update UI with discovered drivers
                Update-DriverSelectionUI -Drivers $drivers
            
                $scanDuration = (Get-Date) - $scanStartTime
                $signedCount = ($drivers | Where-Object { $_.IsSigned() }).Count
                $unsignedCount = $drivers.Count - $signedCount
            
                Update-ApplicationProgress 100.0 "Found $($drivers.Count) drivers ($signedCount signed, $unsignedCount unsigned)"
            
                Write-ApplicationLog "Enhanced driver scan completed in $([math]::Round($scanDuration.TotalSeconds, 1))s" ([LogLevel]::Success)
                Write-ApplicationLog "Results: $($drivers.Count) drivers total ($signedCount signed, $unsignedCount unsigned)" ([LogLevel]::Info)
            
                if ($drivers.Count -gt 0) {
                    Update-WorkflowStep -Step ([WorkflowStep]::Configure)
                
                    # Show processing method recommendation
                    if ($drivers.Count -gt 20) {
                        Write-ApplicationLog "Large driver set detected - batch-style processing recommended for speed" ([LogLevel]::Info)
                    }
                }
            
                if ($unsignedCount -gt 0) {
                    Write-ApplicationLog "Warning: $unsignedCount unsigned drivers detected" ([LogLevel]::Warning)
                }
            }
            catch {
                [System.Windows.MessageBox]::Show(
                    "Driver scan failed: $($_.Exception.Message)", 
                    "Driver Scan Error", 
                    [System.Windows.MessageBoxButton]::OK, 
                    [System.Windows.MessageBoxImage]::Error
                )
                Update-ApplicationProgress 0.0 "Driver scan failed"
                Write-ApplicationLog "Enhanced driver scan failed: $($_.Exception.Message)" ([LogLevel]::Error)
            }
        }
        catch {
            Write-ApplicationLog "Error during enhanced driver scan: $($_.Exception.Message)" ([LogLevel]::Error)
        }
        finally {
            $uiElements.MainProgressBar.IsIndeterminate = $false
            $uiElements.MainProgressBar.Value = 0
            $uiElements.ScanDriversButton.IsEnabled = $true
            $uiElements.ScanDriversButton.Content = "Scan Drivers"
            $script:ApplicationState.SetCurrentState('Idle')
        }
    })

# Helper function to find all checkboxes in the driver list
function Get-AllDriverCheckboxes {
    $checkboxes = @()
    
    foreach ($child in $uiElements.DriverListPanel.Children) {
        try {
            # Skip header borders (manufacturer group headers) - they have TextBlocks as children
            if ($child -is [System.Windows.Controls.Border] -and 
                $child.Child -is [System.Windows.Controls.Grid] -and 
                $child.Child.Children[1] -is [System.Windows.Controls.TextBlock]) {
                continue
            }
            
            # Look for driver item borders (they contain a Grid with a CheckBox)
            if ($child -is [System.Windows.Controls.Border] -and $child.Child -is [System.Windows.Controls.Grid]) {
                $grid = $child.Child
                foreach ($gridChild in $grid.Children) {
                    if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                        $checkboxes += $gridChild
                        break
                    }
                }
            }
            # Fallback: direct Grid containers (for backwards compatibility)
            elseif ($child -is [System.Windows.Controls.Grid]) {
                foreach ($gridChild in $child.Children) {
                    if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                        $checkboxes += $gridChild
                        break
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error processing UI element while finding checkboxes: $($_.Exception.Message)"
        }
    }
    
    Write-Verbose "Found $($checkboxes.Count) checkboxes in driver list"
    return $checkboxes
}

# Helper function to find all checkboxes in the installed driver list
function Get-AllInstalledDriverCheckboxes {
    $checkboxes = @()
    
    foreach ($child in $uiElements.InstalledDriverListPanel.Children) {
        try {
            # Skip header borders and text blocks
            if ($child -is [System.Windows.Controls.TextBlock]) {
                continue
            }
            
            # Look for driver item borders
            if ($child -is [System.Windows.Controls.Border] -and $child.Child -is [System.Windows.Controls.Grid]) {
                $grid = $child.Child
                foreach ($gridChild in $grid.Children) {
                    if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                        $checkboxes += $gridChild
                        break
                    }
                }
            }
            elseif ($child -is [System.Windows.Controls.Grid]) {
                foreach ($gridChild in $child.Children) {
                    if ($gridChild -is [System.Windows.Controls.CheckBox]) {
                        $checkboxes += $gridChild
                        break
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error processing UI element while finding installed driver checkboxes: $($_.Exception.Message)"
        }
    }
    
    Write-Verbose "Found $($checkboxes.Count) checkboxes in installed driver list"
    return $checkboxes
}

# Driver Selection Bulk Action Handlers - FIXED
$uiElements.SelectAllDriversButton.Add_Click({
        try {
            Write-Verbose "User requested to select all drivers"
            $selectedCount = 0
        
            $checkboxes = Get-AllDriverCheckboxes
        
            foreach ($checkBox in $checkboxes) {
                try {
                    if ($checkBox.IsChecked -ne $true) {
                        $checkBox.IsChecked = $true
                        $selectedCount++
                    }
                }
                catch {
                    Write-Verbose "Error selecting checkbox"
                }
            }
        
            Write-ApplicationLog "Selected all drivers ($selectedCount drivers)" ([LogLevel]::Info)
            Write-Verbose "Total checkboxes found and processed: $($checkboxes.Count)"
        }
        catch {
            Write-Warning "Error selecting all drivers: $($_.Exception.Message)"
        }
    })

$uiElements.DeselectAllDriversButton.Add_Click({
        try {
            Write-Verbose "User requested to deselect all drivers"
            $deselectedCount = 0
        
            $checkboxes = Get-AllDriverCheckboxes
        
            foreach ($checkBox in $checkboxes) {
                try {
                    if ($checkBox.IsChecked -eq $true) {
                        $checkBox.IsChecked = $false
                        $deselectedCount++
                    }
                }
                catch {
                    Write-Verbose "Error deselecting checkbox"
                }
            }
        
            Write-ApplicationLog "Deselected all drivers ($deselectedCount drivers)" ([LogLevel]::Info)
            Write-Verbose "Total checkboxes found and processed: $($checkboxes.Count)"
        }
        catch {
            Write-Warning "Error deselecting all drivers: $($_.Exception.Message)"
        }
    })

# Security Warning for Unsigned Drivers
$uiElements.ForceUnsignedCheckBox.Add_Checked({
        try {
            Write-Verbose "User attempting to enable unsigned driver installation"
        
            $result = [System.Windows.MessageBox]::Show(
                "WARNING: Forcing unsigned driver installation can compromise system security.`n`nUnsigned drivers may contain malicious code or cause system instability.`n`nOnly proceed if you trust the driver sources completely.`n`nDo you want to enable unsigned driver installation?", 
                "Security Warning - Unsigned Drivers", 
                [System.Windows.MessageBoxButton]::YesNo, 
                [System.Windows.MessageBoxImage]::Warning
            )
        
            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                $uiElements.ForceUnsignedCheckBox.IsChecked = $false
                Write-ApplicationLog "User declined unsigned driver installation" ([LogLevel]::Info)
            }
            else {
                Write-ApplicationLog "User enabled unsigned driver installation" ([LogLevel]::Warning)
            }
        }
        catch {
            Write-Warning "Error handling unsigned driver checkbox"
            $uiElements.ForceUnsignedCheckBox.IsChecked = $false
        }
    })

Write-Verbose "Enhanced event handlers with driver management configured successfully"
#endregion

#region 13. Simplified Core Workflow Implementation
<#
.SYNOPSIS
    Simplified core workflow based on batch processing reliability patterns.
    
.DESCRIPTION
    This region implements a streamlined driver injection workflow inspired by
    the proven batch file approach:
    - Clean, simple mount/inject/unmount cycles
    - Reduced complexity while maintaining enterprise features
    - Batch-style reliability with PowerShell flexibility
    - User-controlled paths and driver selection
#>

<#
.SYNOPSIS
    Main driver injection workflow with batch-inspired simplicity.
    
.DESCRIPTION
    Simplified workflow that combines batch reliability with PowerShell features:
    - Simple mount -> inject -> commit/unmount cycles per index
    - User maintains full control over all paths and selections
    - Enhanced error handling without complexity
    - Option for batch-style recursive or individual driver processing
    
.PARAMETER WimFilePath
    Path to the Windows Image file to modify (user-selected)
    
.PARAMETER SelectedDrivers
    Array of DriverInfo objects representing user-selected drivers
    
.PARAMETER MountDirectoryPath
    Temporary directory path for mounting WIM images (user-specified)
    
.PARAMETER ForceUnsignedDrivers
    Whether to force installation of unsigned drivers
    
.PARAMETER UseRecursiveMethod
    Whether to use batch-style recursive injection (faster, less control)
    
.OUTPUTS
    WorkflowResult object with comprehensive operation results
#>
function Invoke-DriverInjectionWorkflow {
    [CmdletBinding()]
    [OutputType([WorkflowResult])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$WimFilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [DriverInfo[]]$SelectedDrivers,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountDirectoryPath,
        
        [Parameter(Mandatory = $false)]
        [string]$DriverFolderPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForceUnsignedDrivers,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseRecursiveMethod
    )
    
    begin {
        $result = [WorkflowResult]::new()
        $workflowStartTime = [DateTime]::Now
    }
    
    process {
        try {
            Write-ApplicationLog "Starting simplified driver injection workflow..." ([LogLevel]::Info)
            Write-ApplicationLog "Target WIM: $([System.IO.Path]::GetFileName($WimFilePath))" ([LogLevel]::Info)
            Write-ApplicationLog "Selected drivers: $($SelectedDrivers.Count)" ([LogLevel]::Info)
            Write-ApplicationLog "Mount directory: $MountDirectoryPath" ([LogLevel]::Info)
            Write-ApplicationLog "Method: $(if ($UseRecursiveMethod) { 'Batch-style recursive' } else { 'Individual selection' })" ([LogLevel]::Info)
            
            Update-ApplicationProgress 10 "Initializing workflow..."
            
            # Step 1: Quick validation (simplified)
            $unsignedDrivers = $SelectedDrivers | Where-Object { -not $_.IsSigned() }
            if ($unsignedDrivers.Count -gt 0 -and -not $ForceUnsignedDrivers) {
                $result.ErrorInfo = @{
                    Type    = "UnsignedDriversWithoutPermission"
                    Message = "Found $($unsignedDrivers.Count) unsigned drivers but force unsigned option is not enabled"
                    Details = "Enable 'Force installation of unsigned drivers' option to proceed."
                }
                return $result
            }
            
            # Step 2: Get WIM indexes
            Update-ApplicationProgress 20 "Reading WIM indexes..."
            try {
                $indexes = Get-WimIndexes -WimFilePath $WimFilePath
                Write-ApplicationLog "Found $($indexes.Count) WIM indexes: $($indexes -join ', ')" ([LogLevel]::Success)
            }
            catch {
                $result.ErrorInfo = @{
                    Type    = "WimReadError"
                    Message = $_.Exception.Message
                    Details = "Could not read WIM file indexes."
                }
                return $result
            }
            
            # Step 3: Process each index with simplified approach
            $successfulIndexes = 0
            $failedIndexes = 0
            $progressPerIndex = 60.0 / $indexes.Count  # 60% of progress for processing
            $currentProgress = 30.0  # Start at 30%
            
            Write-ApplicationLog "Processing $($indexes.Count) indexes..." ([LogLevel]::Info)
            
            foreach ($index in $indexes) {
                $indexStartTime = [DateTime]::Now
                Update-ApplicationProgress ([math]::Round($currentProgress, 1)) "Processing index $index..."
                
                try {
                    if ($UseRecursiveMethod) {
                        # Batch-style: use the user-selected driver folder
                        $driverFolder = if (-not [string]::IsNullOrWhiteSpace($DriverFolderPath)) { $DriverFolderPath } else { [System.IO.Path]::GetDirectoryName($SelectedDrivers[0].FullPath) }
                        $success = Invoke-SimpleBatchStyleProcessing -WimFilePath $WimFilePath -Index $index -MountPath $MountDirectoryPath -DriverFolder $driverFolder -ForceUnsigned:$ForceUnsignedDrivers
                    }
                    else {
                        # Individual: process selected drivers one by one
                        $success = Invoke-SimpleIndividualProcessing -WimFilePath $WimFilePath -Index $index -MountPath $MountDirectoryPath -Drivers $SelectedDrivers -ForceUnsigned:$ForceUnsignedDrivers
                    }
                    
                    $indexDuration = ([DateTime]::Now - $indexStartTime).TotalSeconds
                    
                    if ($success) {
                        Write-ApplicationLog "Index $index processed successfully in $([math]::Round($indexDuration, 1))s" ([LogLevel]::Success)
                        $successfulIndexes++
                    }
                    else {
                        Write-ApplicationLog "Index $index failed to process" ([LogLevel]::Error)
                        $failedIndexes++
                    }
                }
                catch {
                    Write-ApplicationLog "Error processing index ${index}: $($_.Exception.Message)" ([LogLevel]::Error)
                    $failedIndexes++
                }
                
                $currentProgress += $progressPerIndex
            }
            
            # Step 4: Results
            $result.ProcessedIndexes = $indexes.Count
            $result.SuccessfulIndexes = $successfulIndexes
            $result.FailedIndexes = $failedIndexes
            $result.Duration = [DateTime]::Now - $workflowStartTime
            
            if ($failedIndexes -eq 0) {
                Update-ApplicationProgress 100.0 "Driver injection completed successfully!"
                $result.Success = $true
                $result.Message = "All indexes processed successfully!"
                $result.Details = @"
Successfully processed: $successfulIndexes/$($indexes.Count) indexes
Duration: $([math]::Round($result.Duration.TotalMinutes, 1)) minutes
Method: $(if ($UseRecursiveMethod) { 'Batch-style recursive' } else { 'Individual driver selection' })
"@
            }
            elseif ($successfulIndexes -gt 0) {
                Update-ApplicationProgress 100.0 "Driver injection completed with some failures"
                $result.Success = $true
                $result.Message = "Partially successful - some indexes failed"
                $result.Details = @"
Successfully processed: $successfulIndexes/$($indexes.Count) indexes
Failed indexes: $failedIndexes
Duration: $([math]::Round($result.Duration.TotalMinutes, 1)) minutes
"@
            }
            else {
                Update-ApplicationProgress 0.0 "Driver injection failed"
                $result.ErrorInfo = @{
                    Type    = "AllIndexesFailed"
                    Message = "All indexes failed to process"
                    Details = "Check the log for specific error details."
                }
            }
            
            return $result
        }
        catch {
            $result.ErrorInfo = @{
                Type    = "WorkflowException"
                Message = $_.Exception.Message
                Details = "Unexpected error during workflow execution."
            }
            $result.Duration = [DateTime]::Now - $workflowStartTime
            return $result
        }
        finally {
            # Simple cleanup
            try {
                if ([System.IO.Directory]::Exists($MountDirectoryPath)) {
                    $items = Get-ChildItem -Path $MountDirectoryPath -Force -ErrorAction SilentlyContinue
                    if ($items.Count -gt 0) {
                        $cleanupArgs = @{ MountDir = $MountDirectoryPath }
                        Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $cleanupArgs | Out-Null
                    }
                }
            }
            catch {
                Write-ApplicationLog "Final cleanup warning: $($_.Exception.Message)" ([LogLevel]::Warning)
            }
        }
    }
}

<#
.SYNOPSIS
    Simple batch-style processing: mount -> recursive inject -> commit/unmount.
    
.DESCRIPTION
    Replicates the batch file's simple and reliable approach:
    - One mount operation
    - One recursive driver injection command
    - One commit/unmount operation
    - Minimal complexity, maximum reliability
    
.PARAMETER WimFilePath
    Path to the WIM file
    
.PARAMETER Index
    Index number to process
    
.PARAMETER MountPath
    Mount directory path
    
.PARAMETER DriverFolder
    Folder containing drivers (will be processed recursively)
    
.PARAMETER ForceUnsigned
    Whether to force unsigned driver installation
    
.OUTPUTS
    Boolean indicating success
#>
function Invoke-SimpleBatchStyleProcessing {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WimFilePath,
        
        [Parameter(Mandatory = $true)]
        [int]$Index,
        
        [Parameter(Mandatory = $true)]
        [string]$MountPath,
        
        [Parameter(Mandatory = $true)]
        [string]$DriverFolder,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForceUnsigned
    )
    
    process {
        try {
            Write-ApplicationLog "Batch-style processing: Index $Index" ([LogLevel]::Info)
            
            if (-not (Clear-MountDirectory -MountPath $MountPath)) {
                Write-ApplicationLog "Failed to prepare mount directory" ([LogLevel]::Error)
                return $false
            }
            
            $mountArgs = @{
                ImageFile = $WimFilePath
                Index     = $Index
                MountDir  = $MountPath
            }
            
            $mountResult = Invoke-EnhancedDismOperation -Operation "/Mount-Image" -Arguments $mountArgs -TimeoutMs 1200000
            if (-not $mountResult.Success) {
                Write-ApplicationLog "Mount failed: $($mountResult.StandardError)" ([LogLevel]::Error)
                return $false
            }
            
            Start-Sleep -Milliseconds 3000
            if (-not (Test-Path ([System.IO.Path]::Combine($MountPath, "Windows")))) {
                Write-ApplicationLog "Mount verification failed" ([LogLevel]::Error)
                return $false
            }
            
            $driverArgs = @{
                Image   = $MountPath
                Driver  = $DriverFolder
                Recurse = $true
            }
            if ($ForceUnsigned) { $driverArgs.ForceUnsigned = $true }
            
            $driverResult = Invoke-EnhancedDismOperation -Operation "/Add-Driver" -Arguments $driverArgs -TimeoutMs 600000
            
            # --- CORRECTED UNMOUNT CALL ---
            $unmountArgs = @{
                MountDir = $MountPath
                Commit   = $true
            }
            $unmountResult = Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $unmountArgs -TimeoutMs 180000
            
            if ($driverResult.Success -and $unmountResult.Success) {
                Write-ApplicationLog "Batch-style processing successful for index $Index" ([LogLevel]::Success)
                return $true
            }
            else {
                Write-ApplicationLog "Batch-style processing failed - Driver: $($driverResult.Success), Unmount: $($unmountResult.Success)" ([LogLevel]::Error)
                if (-not $unmountResult.Success) {
                    $discardArgs = @{ MountDir = $MountPath; Discard = $true }
                    Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $discardArgs -TimeoutMs 180000 | Out-Null
                }
                return $false
            }
        }
        catch {
            Write-ApplicationLog "Exception in batch-style processing: $($_.Exception.Message)" ([LogLevel]::Error)
            try {
                $emergencyArgs = @{ MountDir = $MountPath; Discard = $true }
                Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $emergencyArgs | Out-Null
            }
            catch { }
            return $false
        }
    }
}

<#
.SYNOPSIS
    Simple individual processing: mount -> inject selected drivers -> commit/unmount.
    
.DESCRIPTION
    Processes user-selected drivers individually with simplified logic:
    - One mount operation  
    - Individual driver injection (user maintains control)
    - One commit/unmount operation
    - Commit if any drivers succeed
    
.PARAMETER WimFilePath
    Path to the WIM file
    
.PARAMETER Index
    Index number to process
    
.PARAMETER MountPath
    Mount directory path
    
.PARAMETER Drivers
    Array of user-selected drivers
    
.PARAMETER ForceUnsigned
    Whether to force unsigned driver installation
    
.OUTPUTS
    Boolean indicating success
#>
function Invoke-SimpleIndividualProcessing {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WimFilePath,
        
        [Parameter(Mandatory = $true)]
        [int]$Index,
        
        [Parameter(Mandatory = $true)]
        [string]$MountPath,
        
        [Parameter(Mandatory = $true)]
        [DriverInfo[]]$Drivers,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForceUnsigned
    )
    
    process {
        try {
            Write-ApplicationLog "Individual processing: Index $Index with $($Drivers.Count) drivers" ([LogLevel]::Info)
            
            if (-not (Clear-MountDirectory -MountPath $MountPath)) {
                Write-ApplicationLog "Failed to prepare mount directory" ([LogLevel]::Error)
                return $false
            }
            
            $mountArgs = @{
                ImageFile = $WimFilePath
                Index     = $Index
                MountDir  = $MountPath
            }
            
            $mountResult = Invoke-EnhancedDismOperation -Operation "/Mount-Image" -Arguments $mountArgs -TimeoutMs 1200000
            if (-not $mountResult.Success) {
                Write-ApplicationLog "Mount failed: $($mountResult.StandardError)" ([LogLevel]::Error)
                return $false
            }
            
            Start-Sleep -Milliseconds 3000
            if (-not (Test-Path ([System.IO.Path]::Combine($MountPath, "Windows")))) {
                Write-ApplicationLog "Mount verification failed" ([LogLevel]::Error)
                return $false
            }
            
            $successCount = 0
            $failureCount = 0
            
            foreach ($driver in $Drivers) {
                try {
                    $driverArgs = @{ Image = $MountPath; Driver = $driver.FullPath }
                    if ($ForceUnsigned) { $driverArgs.ForceUnsigned = $true }
                    
                    $result = Invoke-EnhancedDismOperation -Operation "/Add-Driver" -Arguments $driverArgs -TimeoutMs 120000
                    
                    if ($result.Success) {
                        $successCount++
                        Write-ApplicationLog "Installed: $($driver.Name)" ([LogLevel]::Success)
                    }
                    else {
                        $failureCount++
                        Write-ApplicationLog "Failed: $($driver.Name) - $($result.StandardError)" ([LogLevel]::Warning)
                    }
                }
                catch {
                    $failureCount++
                    Write-ApplicationLog "Error installing $($driver.Name): $($_.Exception.Message)" ([LogLevel]::Warning)
                }
            }
            
            # --- CORRECTED UNMOUNT CALL ---
            $shouldCommit = ($successCount -gt 0)
            $unmountArgs = @{
                MountDir = $MountPath
                Commit   = $shouldCommit
                Discard  = -not $shouldCommit
            }
            $unmountResult = Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $unmountArgs -TimeoutMs 180000
            
            if ($unmountResult.Success) {
                if ($shouldCommit) {
                    Write-ApplicationLog "Individual processing successful: $successCount/$($Drivers.Count) drivers installed" ([LogLevel]::Success)
                }
                else {
                    Write-ApplicationLog "Individual processing completed but no drivers were installed; changes discarded." ([LogLevel]::Warning)
                }
                return $shouldCommit
            }
            else {
                Write-ApplicationLog "Unmount failed: $($unmountResult.StandardError)" ([LogLevel]::Error)
                return $false
            }
        }
        catch {
            Write-ApplicationLog "Exception in individual processing: $($_.Exception.Message)" ([LogLevel]::Error)
            try {
                $emergencyArgs = @{ MountDir = $MountPath; Discard = $true }
                Invoke-EnhancedDismOperation -Operation "/Unmount-Image" -Arguments $emergencyArgs | Out-Null
            }
            catch { }
            return $false
        }
    }
}

Write-Verbose "Simplified core workflow with batch processing reliability loaded successfully"
#endregion

#region 14. Enhanced UI Management Functions
<#
.SYNOPSIS
    Enhanced UI management and driver selection interface functions with installed driver management.
#>

function Update-DriverSelectionUI {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [DriverInfo[]]$Drivers
    )
    
    try {
        Write-Verbose "Updating driver selection UI with $($Drivers.Count) drivers"
        
        $driverListPanel = $uiElements.DriverListPanel
        $driverSelectionCard = $uiElements.DriverSelectionCard
        $driverSummaryText = $uiElements.DriverSummaryText
        $selectAllButton = $uiElements.SelectAllDriversButton
        $deselectAllButton = $uiElements.DeselectAllDriversButton
        
        if (-not $driverListPanel) { 
            Write-Warning "Driver list panel not available"
            return 
        }
        
        # Clear existing elements properly to prevent resource leaks
        try {
            foreach ($child in $driverListPanel.Children) {
                if ($child -is [System.IDisposable]) {
                    $child.Dispose()
                }
            }
        }
        catch {
            Write-Verbose "Error disposing UI elements: $($_.Exception.Message)"
        }
        
        $driverListPanel.Children.Clear()
        $driverSelectionCard.Visibility = [System.Windows.Visibility]::Visible
        
        if ($Drivers.Count -eq 0) {
            $driverSummaryText.Text = "No driver (.inf) files found in the selected directory."
            
            # Create simpler empty state to reduce resource usage
            $emptyStateText = [System.Windows.Controls.TextBlock]::new()
            $emptyStateText.Text = "No drivers found. Please check folder contents and permissions."
            $emptyStateText.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $emptyStateText.FontSize = 14
            $emptyStateText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
            $emptyStateText.Margin = [System.Windows.Thickness]::new(20)
            
            $driverListPanel.Children.Add($emptyStateText) | Out-Null
            
            $selectAllButton.Visibility = [System.Windows.Visibility]::Collapsed
            $deselectAllButton.Visibility = [System.Windows.Visibility]::Collapsed
            
            Update-DriverSelectionCount
            return
        }
        
        $selectAllButton.Visibility = [System.Windows.Visibility]::Visible
        $deselectAllButton.Visibility = [System.Windows.Visibility]::Visible

        $signedCount = @($Drivers | Where-Object { $_.IsSigned() }).Count
        $unsignedCount = $Drivers.Count - $signedCount
        
        # Judge each driver's suitability for the selected image type.
        $imageType = $script:CurrentWimImageType
        $imageArch = $script:CurrentWimArchitecture
        $imageLabel = 'this image'
        if ($imageType -eq [WimImageType]::Boot) { $imageLabel = 'boot.wim (Windows PE)' }
        elseif ($imageType -eq [WimImageType]::Install) { $imageLabel = 'install.wim' }
        
        $suitableEntries = [System.Collections.Generic.List[object]]::new()
        $notRecommendedEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($driver in $Drivers) {
            try {
                $judgment = Test-DriverSuitabilityForImage -Driver $driver -ImageType $imageType -ImageArchitecture $imageArch
                $entry = [PSCustomObject]@{ Driver = $driver; Reason = $judgment.Reason; Class = $judgment.Class }
                if ($judgment.Suitable) { $suitableEntries.Add($entry) } else { $notRecommendedEntries.Add($entry) }
            }
            catch {
                $notRecommendedEntries.Add([PSCustomObject]@{ Driver = $driver; Reason = "Could not evaluate: $($_.Exception.Message)"; Class = 'Unknown' })
            }
        }
        
        $driverSummaryText.Text = "Found $($Drivers.Count) drivers ($signedCount signed, $unsignedCount unsigned). For ${imageLabel}: $($suitableEntries.Count) recommended, $($notRecommendedEntries.Count) not recommended."
        Write-ApplicationLog "Suitability for ${imageLabel}: $($suitableEntries.Count) recommended, $($notRecommendedEntries.Count) not recommended" ([LogLevel]::Info)
        
        # Limit number of drivers displayed per section to prevent resource exhaustion
        $maxDriversToDisplay = $script:Configuration.DriverDisplayBatchSize
        
        # Section 1: Recommended (suitable) drivers, pre-checked
        $recommendedHeader = [System.Windows.Controls.TextBlock]::new()
        $recommendedHeader.Text = "[OK] Recommended for ${imageLabel} ($($suitableEntries.Count))"
        $recommendedHeader.FontWeight = [System.Windows.FontWeights]::SemiBold
        $recommendedHeader.FontSize = 15
        $recommendedHeader.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
        $recommendedHeader.Margin = [System.Windows.Thickness]::new(12, 16, 12, 8)
        $driverListPanel.Children.Add($recommendedHeader) | Out-Null
        
        if ($suitableEntries.Count -eq 0) {
            $noneText = [System.Windows.Controls.TextBlock]::new()
            $noneText.Text = "No drivers in this folder are recommended for ${imageLabel}."
            $noneText.FontSize = 12
            $noneText.FontStyle = [System.Windows.FontStyles]::Italic
            $noneText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(138, 136, 134))
            $noneText.Margin = [System.Windows.Thickness]::new(16, 4, 0, 4)
            $driverListPanel.Children.Add($noneText) | Out-Null
        }
        else {
            $suitableToShow = $suitableEntries
            if ($suitableEntries.Count -gt $maxDriversToDisplay) { $suitableToShow = $suitableEntries | Select-Object -First $maxDriversToDisplay }
            foreach ($entry in ($suitableToShow | Sort-Object { $_.Driver.Name })) {
                try {
                    $driverPanel = New-DriverListItem -Driver $entry.Driver -InitiallyChecked
                    $driverListPanel.Children.Add($driverPanel) | Out-Null
                }
                catch {
                    Write-Warning "Failed to create UI item for driver: $($entry.Driver.Name)"
                }
            }
        }
        
        # Section 2: Not-recommended drivers, unchecked with reason (user can override)
        $notRecommendedHeader = [System.Windows.Controls.TextBlock]::new()
        $notRecommendedHeader.Text = "[!] Not recommended for ${imageLabel} ($($notRecommendedEntries.Count)) - select to override"
        $notRecommendedHeader.FontWeight = [System.Windows.FontWeights]::SemiBold
        $notRecommendedHeader.FontSize = 15
        $notRecommendedHeader.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(196, 94, 0))
        $notRecommendedHeader.Margin = [System.Windows.Thickness]::new(12, 20, 12, 8)
        $driverListPanel.Children.Add($notRecommendedHeader) | Out-Null
        
        if ($notRecommendedEntries.Count -eq 0) {
            $noneText2 = [System.Windows.Controls.TextBlock]::new()
            $noneText2.Text = "All scanned drivers are suitable for ${imageLabel}."
            $noneText2.FontSize = 12
            $noneText2.FontStyle = [System.Windows.FontStyles]::Italic
            $noneText2.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(138, 136, 134))
            $noneText2.Margin = [System.Windows.Thickness]::new(16, 4, 0, 4)
            $driverListPanel.Children.Add($noneText2) | Out-Null
        }
        else {
            $notRecommendedToShow = $notRecommendedEntries
            $showingLimited = $false
            if ($notRecommendedEntries.Count -gt $maxDriversToDisplay) {
                $notRecommendedToShow = $notRecommendedEntries | Select-Object -First $maxDriversToDisplay
                $showingLimited = $true
            }
            foreach ($entry in ($notRecommendedToShow | Sort-Object { $_.Driver.Name })) {
                try {
                    $driverPanel = New-DriverListItem -Driver $entry.Driver -Note $entry.Reason
                    $driverListPanel.Children.Add($driverPanel) | Out-Null
                }
                catch {
                    Write-Warning "Failed to create UI item for driver: $($entry.Driver.Name)"
                }
            }
            if ($showingLimited) {
                $limitWarning = [System.Windows.Controls.TextBlock]::new()
                $limitWarning.Text = "[!] Showing first $maxDriversToDisplay of $($notRecommendedEntries.Count) not-recommended drivers."
                $limitWarning.FontStyle = [System.Windows.FontStyles]::Italic
                $limitWarning.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(255, 140, 0))
                $limitWarning.Margin = [System.Windows.Thickness]::new(12, 8, 12, 8)
                $limitWarning.TextWrapping = [System.Windows.TextWrapping]::Wrap
                $driverListPanel.Children.Add($limitWarning) | Out-Null
            }
        }
        
        Update-DriverSelectionCount
        Write-Verbose "Driver selection UI updated successfully"
    }
    catch {
        Write-Warning "Error updating driver selection UI: $($_.Exception.Message)"
    }
}

function Update-InstalledDriverUI {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [InstalledDriverInfo[]]$Drivers
    )
    
    try {
        Write-Verbose "Updating installed driver UI with $($Drivers.Count) drivers"
        
        $installedDriverListPanel = $uiElements.InstalledDriverListPanel
        $removeButton = $uiElements.RemoveDriversButton
        $exportButton = $uiElements.ExportDriversButton
        
        if (-not $installedDriverListPanel) { 
            Write-Warning "Installed driver list panel not available"
            return 
        }
        
        # Clear existing elements
        $installedDriverListPanel.Children.Clear()
        
        if ($Drivers.Count -eq 0) {
            $emptyStateText = [System.Windows.Controls.TextBlock]::new()
            $emptyStateText.Text = "No drivers found in the WIM file. Use 'Inventory Drivers' to scan for installed drivers."
            $emptyStateText.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $emptyStateText.FontSize = 14
            $emptyStateText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
            $emptyStateText.Margin = [System.Windows.Thickness]::new(20)
            $emptyStateText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(138, 136, 134))
            
            $installedDriverListPanel.Children.Add($emptyStateText) | Out-Null
            
            $removeButton.IsEnabled = $false
            $exportButton.IsEnabled = $false
            Update-InstalledDriverCounts
            return
        }
        
        $removeButton.IsEnabled = $true
        $exportButton.IsEnabled = $true
        
        # Group drivers by class for better organization
        $groupedDrivers = $Drivers | Group-Object ClassName | Sort-Object Name
        
        Write-Verbose "Organizing installed drivers into $($groupedDrivers.Count) class groups"
        
        foreach ($group in $groupedDrivers) {
            # Class header
            $headerText = [System.Windows.Controls.TextBlock]::new()
            $headerText.Text = "[+] $($group.Name) ($($group.Count) drivers)"
            $headerText.FontWeight = [System.Windows.FontWeights]::SemiBold
            $headerText.FontSize = 15
            $headerText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 120, 212))
            $headerText.Margin = [System.Windows.Thickness]::new(12, 16, 12, 8)
            
            $installedDriverListPanel.Children.Add($headerText) | Out-Null
            
            foreach ($driver in ($group.Group | Sort-Object ProviderName, OriginalFileName)) {
                try {
                    $driverPanel = New-InstalledDriverListItem -Driver $driver
                    $installedDriverListPanel.Children.Add($driverPanel) | Out-Null
                }
                catch {
                    Write-Warning "Failed to create UI item for installed driver: $($driver.PublishedName)"
                }
            }
        }
        
        Update-InstalledDriverCounts
        Write-Verbose "Installed driver UI updated successfully"
    }
    catch {
        Write-Warning "Error updating installed driver UI: $($_.Exception.Message)"
    }
}

function New-DriverListItem {
    param(
        [Parameter(Mandatory = $true)]
        [DriverInfo]$Driver,

        [Parameter(Mandatory = $false)]
        [switch]$InitiallyChecked,

        [Parameter(Mandatory = $false)]
        [string]$Note = ''
    )
    
    try {
        $grid = [System.Windows.Controls.Grid]::new()
        $grid.Margin = [System.Windows.Thickness]::new(16, 4, 0, 4)
        
        $columns = @(
            [System.Windows.Controls.ColumnDefinition]::new(),
            [System.Windows.Controls.ColumnDefinition]::new(),
            [System.Windows.Controls.ColumnDefinition]::new(),
            [System.Windows.Controls.ColumnDefinition]::new()
        )
        $columns[0].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $columns[1].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $columns[2].Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $columns[3].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        
        foreach ($col in $columns) {
            $grid.ColumnDefinitions.Add($col) | Out-Null
        }
        
        $checkBox = [System.Windows.Controls.CheckBox]::new()
        $checkBox.IsChecked = [bool]$InitiallyChecked
        $checkBox.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
        $checkBox.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $checkBox.Tag = $Driver
        
        $checkBox.Add_Checked({ Update-DriverSelectionCount })
        $checkBox.Add_Unchecked({ Update-DriverSelectionCount })
        
        [System.Windows.Controls.Grid]::SetColumn($checkBox, 0)
        $grid.Children.Add($checkBox) | Out-Null
        
        $iconBorder = [System.Windows.Controls.Border]::new()
        $iconBorder.Width = 20
        $iconBorder.Height = 20
        $iconBorder.CornerRadius = [System.Windows.CornerRadius]::new(10)
        $iconBorder.Margin = [System.Windows.Thickness]::new(0, 0, 12, 0)
        $iconBorder.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        
        $icon = [System.Windows.Controls.TextBlock]::new()
        $icon.FontSize = 12
        $icon.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
        $icon.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        
        if ($Driver.IsSigned()) {
            $icon.Text = "+"
            $icon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Colors]::White)
            $iconBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
            $iconBorder.ToolTip = "Digitally Signed Driver"
        }
        else {
            $icon.Text = "!"
            $icon.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Colors]::White)
            $iconBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(209, 52, 56))
            $iconBorder.ToolTip = "Unsigned Driver - Security Risk"
        }
        
        $iconBorder.Child = $icon
        [System.Windows.Controls.Grid]::SetColumn($iconBorder, 1)
        $grid.Children.Add($iconBorder) | Out-Null
        
        $infoPanel = [System.Windows.Controls.StackPanel]::new()
        
        $nameText = [System.Windows.Controls.TextBlock]::new()
        $nameText.Text = $Driver.Name
        $nameText.FontWeight = [System.Windows.FontWeights]::SemiBold
        $nameText.FontSize = 13
        $infoPanel.Children.Add($nameText) | Out-Null
        
        $detailsText = [System.Windows.Controls.TextBlock]::new()
        $architecture = if ([string]::IsNullOrWhiteSpace($Driver.Architecture)) { "Unknown" } else { $Driver.Architecture }
        $detailsText.Text = "Version: $($Driver.Version) | Date: $($Driver.Date) | Architecture: $architecture"
        $detailsText.FontSize = 11
        $detailsText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(96, 94, 92))
        $detailsText.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)
        $infoPanel.Children.Add($detailsText) | Out-Null
        
        if (-not [string]::IsNullOrWhiteSpace($Note)) {
            $noteText = [System.Windows.Controls.TextBlock]::new()
            $noteText.Text = $Note
            $noteText.FontSize = 11
            $noteText.FontStyle = [System.Windows.FontStyles]::Italic
            $noteText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(196, 94, 0))
            $noteText.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)
            $noteText.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $infoPanel.Children.Add($noteText) | Out-Null
        }
        
        [System.Windows.Controls.Grid]::SetColumn($infoPanel, 2)
        $grid.Children.Add($infoPanel) | Out-Null
        
        $sizeText = [System.Windows.Controls.TextBlock]::new()
        $sizeText.Text = $Driver.GetSizeFormatted()
        $sizeText.FontSize = 11
        $sizeText.FontWeight = [System.Windows.FontWeights]::SemiBold
        $sizeText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(0, 120, 212))
        $sizeText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
        $sizeText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        
        [System.Windows.Controls.Grid]::SetColumn($sizeText, 3)
        $grid.Children.Add($sizeText) | Out-Null
        
        Write-Verbose "Created list item for driver: $($Driver.Name)"
        return $grid
    }
    catch {
        Write-Warning "Error creating driver list item for $($Driver.Name): $($_.Exception.Message)"
        
        $fallbackGrid = [System.Windows.Controls.Grid]::new()
        $fallbackText = [System.Windows.Controls.TextBlock]::new()
        $fallbackText.Text = "Error loading driver: $($Driver.Name)"
        $fallbackText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(209, 52, 56))
        $fallbackGrid.Children.Add($fallbackText) | Out-Null
        return $fallbackGrid
    }
}

function New-InstalledDriverListItem {
    param(
        [Parameter(Mandatory = $true)]
        [InstalledDriverInfo]$Driver
    )
    
    try {
        $grid = [System.Windows.Controls.Grid]::new()
        $grid.Margin = [System.Windows.Thickness]::new(16, 4, 0, 4)
        
        $columns = @(
            [System.Windows.Controls.ColumnDefinition]::new(),  # Checkbox
            [System.Windows.Controls.ColumnDefinition]::new(),  # Status icon
            [System.Windows.Controls.ColumnDefinition]::new(),  # Driver info
            [System.Windows.Controls.ColumnDefinition]::new()   # Removal status
        )
        $columns[0].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $columns[1].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $columns[2].Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $columns[3].Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        
        foreach ($col in $columns) {
            $grid.ColumnDefinitions.Add($col) | Out-Null
        }
        
        # Checkbox for removal selection
        $checkBox = [System.Windows.Controls.CheckBox]::new()
        $checkBox.IsChecked = $false
        $checkBox.Margin = [System.Windows.Thickness]::new(0, 0, 10, 0)
        $checkBox.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $checkBox.Tag = $Driver
        $checkBox.IsEnabled = $Driver.CanBeRemoved
        
        if (-not $Driver.CanBeRemoved) {
            $checkBox.ToolTip = $Driver.GetRemovalStatusText()
        }
        
        $checkBox.Add_Checked({ Update-InstalledDriverCounts })
        $checkBox.Add_Unchecked({ Update-InstalledDriverCounts })
        
        [System.Windows.Controls.Grid]::SetColumn($checkBox, 0)
        $grid.Children.Add($checkBox) | Out-Null
        
        # Status icon
        $statusIcon = [System.Windows.Controls.TextBlock]::new()
        $statusIcon.Text = $Driver.GetStatusIcon()
        $statusIcon.FontSize = 16
        $statusIcon.Margin = [System.Windows.Thickness]::new(0, 0, 12, 0)
        $statusIcon.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $statusIcon.ToolTip = $Driver.GetRemovalStatusText()
        
        [System.Windows.Controls.Grid]::SetColumn($statusIcon, 1)
        $grid.Children.Add($statusIcon) | Out-Null
        
        # Driver information
        $infoPanel = [System.Windows.Controls.StackPanel]::new()
        
        $nameText = [System.Windows.Controls.TextBlock]::new()
        $nameText.Text = "$($Driver.OriginalFileName) ($($Driver.PublishedName))"
        $nameText.FontWeight = [System.Windows.FontWeights]::SemiBold
        $nameText.FontSize = 13
        $infoPanel.Children.Add($nameText) | Out-Null
        
        $detailsText = [System.Windows.Controls.TextBlock]::new()
        $detailsText.Text = "Provider: $($Driver.ProviderName) | Version: $($Driver.DriverVersion) | Date: $($Driver.GetFormattedDate())"
        $detailsText.FontSize = 11
        $detailsText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(96, 94, 92))
        $detailsText.Margin = [System.Windows.Thickness]::new(0, 2, 0, 0)
        $infoPanel.Children.Add($detailsText) | Out-Null
        
        [System.Windows.Controls.Grid]::SetColumn($infoPanel, 2)
        $grid.Children.Add($infoPanel) | Out-Null
        
        # Removal status
        $statusPanel = [System.Windows.Controls.StackPanel]::new()
        $statusPanel.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
        
        $statusText = [System.Windows.Controls.TextBlock]::new()
        $statusText.FontSize = 11
        $statusText.FontWeight = [System.Windows.FontWeights]::SemiBold
        $statusText.TextAlignment = [System.Windows.TextAlignment]::Right
        $statusText.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        
        if ($Driver.CanBeRemoved) {
            $statusText.Text = "Removable"
            $statusText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
        }
        else {
            $statusText.Text = "Protected"
            $statusText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(209, 52, 56))
        }
        
        $statusPanel.Children.Add($statusText) | Out-Null
        
        if (-not [string]::IsNullOrWhiteSpace($Driver.Architecture) -and $Driver.Architecture -ne "Unknown") {
            $archText = [System.Windows.Controls.TextBlock]::new()
            $archText.Text = $Driver.Architecture
            $archText.FontSize = 10
            $archText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(138, 136, 134))
            $archText.TextAlignment = [System.Windows.TextAlignment]::Right
            $statusPanel.Children.Add($archText) | Out-Null
        }
        
        [System.Windows.Controls.Grid]::SetColumn($statusPanel, 3)
        $grid.Children.Add($statusPanel) | Out-Null
        
        Write-Verbose "Created installed driver list item for: $($Driver.PublishedName)"
        return $grid
    }
    catch {
        Write-Warning "Error creating installed driver list item for $($Driver.PublishedName): $($_.Exception.Message)"
        
        $fallbackGrid = [System.Windows.Controls.Grid]::new()
        $fallbackText = [System.Windows.Controls.TextBlock]::new()
        $fallbackText.Text = "Error loading driver: $($Driver.PublishedName)"
        $fallbackText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(209, 52, 56))
        $fallbackGrid.Children.Add($fallbackText) | Out-Null
        return $fallbackGrid
    }
}

function Update-DriverSelectionCount {
    try {
        $selectedDrivers = Get-SelectedDrivers
        $unsignedSelected = ($selectedDrivers | Where-Object { -not $_.IsSigned() }).Count
        
        if ($uiElements.SelectedDriverCount) {
            $countText = if ($selectedDrivers.Count -eq 1) { "1 driver selected" } else { "$($selectedDrivers.Count) drivers selected" }
            $uiElements.SelectedDriverCount.Text = $countText
        }
        
        if ($uiElements.UnsignedDriverWarning) {
            if ($selectedDrivers.Count -eq 0) {
                $uiElements.UnsignedDriverWarning.Text = "No drivers selected"
                $uiElements.UnsignedDriverWarning.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(96, 94, 92))
            }
            elseif ($unsignedSelected -gt 0) {
                $warningText = if ($unsignedSelected -eq 1) { "[!] 1 unsigned driver selected" } else { "[!] $unsignedSelected unsigned drivers selected" }
                $uiElements.UnsignedDriverWarning.Text = $warningText
                $uiElements.UnsignedDriverWarning.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(209, 52, 56))
            }
            else {
                $uiElements.UnsignedDriverWarning.Text = "[OK] All selected drivers are digitally signed"
                $uiElements.UnsignedDriverWarning.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
            }
        }
        
        if ($uiElements.StartButton) {
            $canStart = ($selectedDrivers.Count -gt 0) -and -not $script:ApplicationState.IsProcessing()
            $uiElements.StartButton.IsEnabled = $canStart
        }
        
        Write-Verbose "Updated selection count: $($selectedDrivers.Count) total, $unsignedSelected unsigned"
    }
    catch {
        Write-Warning "Error updating driver selection count: $($_.Exception.Message)"
    }
}

function Update-InstalledDriverCounts {
    try {
        $allDrivers = $script:ApplicationState.InstalledDrivers
        $removableDrivers = $allDrivers | Where-Object { $_.CanBeRemoved }
        $selectedForRemoval = Get-SelectedInstalledDrivers
        
        if ($uiElements.InstalledDriverCount) {
            $countText = if ($allDrivers.Count -eq 1) { "1 driver installed" } else { "$($allDrivers.Count) drivers installed" }
            $uiElements.InstalledDriverCount.Text = $countText
        }
        
        if ($uiElements.RemovableDriverCount) {
            $removableText = if ($removableDrivers.Count -eq 1) { "1 removable" } else { "$($removableDrivers.Count) removable" }
            $uiElements.RemovableDriverCount.Text = $removableText
        }
        
        if ($uiElements.SelectedForRemovalCount) {
            $selectedText = if ($selectedForRemoval.Count -eq 1) { "1 selected for removal" } else { "$($selectedForRemoval.Count) selected for removal" }
            $uiElements.SelectedForRemovalCount.Text = $selectedText
        }
        
        if ($uiElements.RemoveDriversButton) {
            $uiElements.RemoveDriversButton.IsEnabled = ($selectedForRemoval.Count -gt 0) -and -not $script:ApplicationState.IsProcessing()
        }
        
        Write-Verbose "Updated installed driver counts: $($allDrivers.Count) total, $($removableDrivers.Count) removable, $($selectedForRemoval.Count) selected"
    }
    catch {
        Write-Warning "Error updating installed driver counts: $($_.Exception.Message)"
    }
}

function Get-SelectedInstalledDrivers {
    try {
        $selectedDrivers = [System.Collections.Generic.List[InstalledDriverInfo]]::new()
        
        if (-not $script:MainWindow) {
            Write-Warning "Main window reference not available"
            return @()
        }
        
        $installedDriverListPanel = $script:MainWindow.FindName("InstalledDriverListPanel")
        if (-not $installedDriverListPanel) {
            Write-Warning "Installed driver list panel not found in UI"
            return @()
        }
        
        # Get all checkboxes
        foreach ($child in $installedDriverListPanel.Children) {
            try {
                # Skip text blocks and headers
                if ($child -is [System.Windows.Controls.TextBlock]) {
                    continue
                }
                
                # Look for driver item containers
                if ($child -is [System.Windows.Controls.Border] -and $child.Child -is [System.Windows.Controls.Grid]) {
                    $grid = $child.Child
                    foreach ($gridChild in $grid.Children) {
                        if ($gridChild -is [System.Windows.Controls.CheckBox] -and $gridChild.IsChecked -eq $true -and $gridChild.Tag) {
                            $driver = $gridChild.Tag -as [InstalledDriverInfo]
                            if ($driver) {
                                $selectedDrivers.Add($driver)
                            }
                        }
                    }
                }
                elseif ($child -is [System.Windows.Controls.Grid]) {
                    foreach ($gridChild in $child.Children) {
                        if ($gridChild -is [System.Windows.Controls.CheckBox] -and $gridChild.IsChecked -eq $true -and $gridChild.Tag) {
                            $driver = $gridChild.Tag -as [InstalledDriverInfo]
                            if ($driver) {
                                $selectedDrivers.Add($driver)
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error processing installed driver UI element: $($_.Exception.Message)"
            }
        }
        
        Write-Verbose "Retrieved $($selectedDrivers.Count) selected installed drivers from UI"
        return $selectedDrivers.ToArray()
    }
    catch {
        Write-Warning "Error getting selected installed drivers: $($_.Exception.Message)"
        return @()
    }
}

Write-Verbose "Enhanced UI management functions with driver management loaded successfully"
#endregion

#region 15. Main Process Control Handlers
<#
.SYNOPSIS
    Simplified application control handlers for start/cancel operations.
    
.DESCRIPTION
    This region implements the main workflow control:
    - Comprehensive pre-execution validation
    - Direct workflow execution (no complex runspaces)
    - Real-time progress monitoring and user feedback
    - Robust cancellation and cleanup mechanisms
#>

# Simplified Start Button Handler - Direct execution instead of complex runspaces
$uiElements.StartButton.Add_Click({
        # Prevent multiple simultaneous operations
        if ($script:ApplicationState.IsProcessing()) {
            Write-Verbose "Operation already in progress - ignoring start request"
            return
        }

        $workflowStartTime = [DateTime]::Now

        try {
            Write-ApplicationLog "User initiated driver injection process" ([LogLevel]::Info)
    
            # Step 1: Comprehensive pre-execution validation
            Write-ApplicationLog "Performing pre-execution validation..." ([LogLevel]::Info)
        
            $validationErrors = [System.Collections.Generic.List[string]]::new()
    
            # Validate WIM file
            $wimValidation = Test-WimFileValidation -WimPath $uiElements.WimFileTextBox.Text
            if (-not $wimValidation.IsValid) {
                $validationErrors.Add("WIM File: $($wimValidation.ErrorMessage)")
            }
    
            # Validate driver selection
            $selectedDrivers = Get-SelectedDrivers
            if ($selectedDrivers.Count -eq 0) {
                $validationErrors.Add("Driver Selection: No drivers selected for injection")
            }
    
            # Validate driver folder is selected
            if ([string]::IsNullOrWhiteSpace($uiElements.DriverFolderTextBox.Text) -or 
                $uiElements.DriverFolderTextBox.Text -eq "No folder selected...") {
                $validationErrors.Add("Driver Folder: No driver folder selected")
            }
    
            # Validate mount directory security
            $mountValidation = Test-SecurePath -Path $uiElements.MountDirTextBox.Text
            if (-not $mountValidation.IsValid) {
                $validationErrors.Add("Mount Directory: $($mountValidation.ErrorMessage)")
            }
            else {
                # --- ADDED VALIDATION START ---
                # Validate mount directory prerequisites (NTFS, Fixed Drive)
                $mountPrereqValidation = Test-MountPathPrerequisites -MountPath $uiElements.MountDirTextBox.Text
                if (-not $mountPrereqValidation.IsValid) {
                    $validationErrors.Add("Mount Directory Prerequisites: $($mountPrereqValidation.ErrorMessage)")
                }
                # --- ADDED VALIDATION END ---
            }
    
            # Validate system requirements
            if (-not (Test-EnhancedAdministratorPrivileges)) {
                $validationErrors.Add("System: Administrator privileges required")
            }
    
            if (-not (Test-DismToolAvailability)) {
                $validationErrors.Add("System: DISM tool not available")
            }
    
            # Show validation errors if any
            if ($validationErrors.Count -gt 0) {
                $errorMessage = "Validation failed:`n`n" + ($validationErrors -join "`n`n")
                [System.Windows.MessageBox]::Show(
                    $errorMessage, 
                    "Validation Error", 
                    [System.Windows.MessageBoxButton]::OK, 
                    [System.Windows.MessageBoxImage]::Warning
                )
                return
            }
    
            # Step 2: Processing method selection
            $unsignedDrivers = $selectedDrivers | Where-Object { -not $_.IsSigned() }
        
            # Handle unsigned drivers
            if ($unsignedDrivers.Count -gt 0 -and -not $uiElements.ForceUnsignedCheckBox.IsChecked) {
                $result = [System.Windows.MessageBox]::Show(
                    "You have selected $($unsignedDrivers.Count) unsigned drivers, but the 'Force unsigned drivers' option is not enabled.`n`nUnsigned drivers pose security risks. Enable unsigned driver installation?", 
                    "Unsigned Drivers Detected", 
                    [System.Windows.MessageBoxButton]::YesNo, 
                    [System.Windows.MessageBoxImage]::Warning
                )
            
                if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                    $uiElements.ForceUnsignedCheckBox.IsChecked = $true
                }
                else {
                    return
                }
            }
        
            # Choose processing method
            $methodChoice = [System.Windows.MessageBox]::Show(
                @"
CHOOSE DRIVER INJECTION METHOD

BATCH-STYLE RECURSIVE (Recommended for speed):
+ Faster processing (like the proven batch approach)
+ Processes entire driver folder recursively  
+ Simple and reliable
* Less granular control over individual drivers

INDIVIDUAL SELECTION (Recommended for control):
+ Process only your selected drivers
+ Full control over each driver
+ Better for mixed driver sets
* Slower processing time

Choose BATCH-STYLE for speed, or INDIVIDUAL for control.
"@, 
                "Choose Processing Method", 
                [System.Windows.MessageBoxButton]::YesNoCancel, 
                [System.Windows.MessageBoxImage]::Question
            )
        
            if ($methodChoice -eq [System.Windows.MessageBoxResult]::Cancel) {
                return
            }
        
            $useBatchStyle = ($methodChoice -eq [System.Windows.MessageBoxResult]::Yes)
            $methodName = if ($useBatchStyle) { "Batch-style recursive" } else { "Individual selection" }
        
            # Step 3: Final confirmation
            $confirmResult = [System.Windows.MessageBox]::Show(
                @"
READY TO INJECT DRIVERS

WIM File: $([System.IO.Path]::GetFileName($wimValidation.ResolvedPath))
Selected Drivers: $($selectedDrivers.Count)
Mount Directory: $($mountValidation.ResolvedPath)
Method: $methodName
Force Unsigned: $($uiElements.ForceUnsignedCheckBox.IsChecked)

This will modify all indexes in the WIM file and cannot be undone.
Ensure you have a backup if this is important.

Proceed with driver injection?
"@, 
                "Confirm Driver Injection", 
                [System.Windows.MessageBoxButton]::YesNo, 
                [System.Windows.MessageBoxImage]::Question
            )
    
            if ($confirmResult -eq [System.Windows.MessageBoxResult]::No) {
                return
            }
    
            # Step 4: Execute simplified workflow
            Write-ApplicationLog "Starting simplified driver injection workflow..." ([LogLevel]::Info)
            Write-ApplicationLog "Method: $methodName" ([LogLevel]::Info)
    
            # Update UI state
            $script:ApplicationState.SetCurrentState([ProcessingState]::Processing)
            $uiElements.StartButton.IsEnabled = $false
            $uiElements.CancelButton.Content = "Cancel Operation"
            Update-WorkflowStep -Step ([WorkflowStep]::Process)
    
            # Execute simplified workflow
            try {
                $workflowResult = Invoke-DriverInjectionWorkflow -WimFilePath $wimValidation.ResolvedPath `
                    -SelectedDrivers $selectedDrivers `
                    -MountDirectoryPath $mountValidation.ResolvedPath `
                    -DriverFolderPath $uiElements.DriverFolderTextBox.Text `
                    -ForceUnsignedDrivers:$uiElements.ForceUnsignedCheckBox.IsChecked `
                    -UseRecursiveMethod:$useBatchStyle
            
                $totalDuration = [DateTime]::Now - $workflowStartTime
            
                # Process results
                if ($workflowResult.Success) {
                    [System.Windows.MessageBox]::Show(
                        @"
DRIVER INJECTION COMPLETED SUCCESSFULLY

$($workflowResult.Message)

DETAILS:
$($workflowResult.Details)

TOTAL TIME: $([math]::Round($totalDuration.TotalMinutes, 1)) minutes

The Windows image has been successfully updated.
"@, 
                        "Success", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Information
                    )
                    Write-ApplicationLog "Driver injection completed successfully" ([LogLevel]::Success)
                }
                else {
                    [System.Windows.MessageBox]::Show(
                        @"
DRIVER INJECTION FAILED

$($workflowResult.ErrorInfo.Message)

$($workflowResult.ErrorInfo.Details)

Check the detailed log for more information.
"@, 
                        "Failed", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Error
                    )
                    Write-ApplicationLog "Driver injection failed: $($workflowResult.ErrorInfo.Message)" ([LogLevel]::Error)
                }
            }
            catch {
                $errorDuration = [DateTime]::Now - $workflowStartTime
                [System.Windows.MessageBox]::Show(
                    "Workflow execution error: $($_.Exception.Message)`n`nDuration: $([math]::Round($errorDuration.TotalMinutes, 1)) minutes", 
                    "Execution Error", 
                    [System.Windows.MessageBoxButton]::OK, 
                    [System.Windows.MessageBoxImage]::Error
                )
                Write-ApplicationLog "Workflow execution error: $($_.Exception.Message)" ([LogLevel]::Error)
            }
            finally {
                # Reset UI state
                $script:ApplicationState.SetCurrentState([ProcessingState]::Idle)
                $uiElements.StartButton.IsEnabled = $true
                $uiElements.CancelButton.Content = "Cancel"
            }
        }
        catch {
            Write-ApplicationLog "Critical error in start button handler: $($_.Exception.Message)" ([LogLevel]::Error)
        
            # Ensure UI state reset
            try {
                $script:ApplicationState.Reset()
                $uiElements.StartButton.IsEnabled = $true
                $uiElements.CancelButton.Content = "Cancel"
                Update-ApplicationProgress 0.0 "Ready to start..."
            }
            catch { }
        }
    })

# Enhanced Cancel Button Handler with comprehensive operation termination
$uiElements.CancelButton.Add_Click({
        if ($script:ApplicationState.CanCancel()) {
            # Show detailed cancellation confirmation
            $result = [System.Windows.MessageBox]::Show(
                @"
CANCEL DRIVER INJECTION OPERATION?

This will immediately stop the current driver injection process.

CANCELLATION EFFECTS:
- Current DISM operations will be terminated
- Any mounted WIM images will be safely unmounted
- Temporary files will be cleaned up
- Progress will be lost and cannot be resumed

SAFETY MEASURES:
- The original WIM file will remain unchanged
- No partial modifications will be committed
- Mount directories will be properly cleaned

The cancellation process may take a few moments to complete safely.

Do you want to cancel the current operation?
"@, 
                "Confirm Operation Cancellation", 
                [System.Windows.MessageBoxButton]::YesNo, 
                [System.Windows.MessageBoxImage]::Warning
            )
    
            if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                try {
                    Write-ApplicationLog "User initiated operation cancellation..." ([LogLevel]::Warning)
                    $script:ApplicationState.SetCurrentState([ProcessingState]::Cancelling)
                    $uiElements.CancelButton.Content = "Cancelling..."
                    $uiElements.CancelButton.IsEnabled = $false
                    Update-ApplicationProgress 0.0 "Cancelling operation..."
            
                    # Enhanced process termination with timeout handling
                    $currentProcess = $script:ApplicationState.GetCurrentProcess()
                    if ($currentProcess) {
                        try {
                            if (-not $currentProcess.HasExited) {
                                Write-ApplicationLog "Terminating active DISM process..." ([LogLevel]::Info)
                                $currentProcess.Kill()
                        
                                # Wait briefly for process termination
                                if (-not $currentProcess.WaitForExit(5000)) {
                                    Write-ApplicationLog "DISM process termination timed out" ([LogLevel]::Warning)
                                }
                                else {
                                    Write-ApplicationLog "DISM process terminated successfully" ([LogLevel]::Info)
                                }
                            }
                        }
                        catch [System.InvalidOperationException] {
                            Write-Verbose "Process already exited during cancellation"
                        }
                        catch {
                            Write-ApplicationLog "Error terminating DISM process: $($_.Exception.Message)" ([LogLevel]::Warning)
                        }
                    }
            
                    # Enhanced cleanup with user choice
                    $mountDir = $uiElements.MountDirTextBox.Text
                    if (-not [string]::IsNullOrWhiteSpace($mountDir)) {
                        $mountValidation = Test-SecurePath -Path $mountDir
                        if ($mountValidation.IsValid) {
                            $cleanupChoice = [System.Windows.MessageBox]::Show(
                                @"
CLEANUP MOUNTED IMAGES

Do you want to automatically clean up any mounted WIM images and temporary files?

RECOMMENDED (Yes):
- Safely unmount any mounted WIM images
- Clean up temporary mount directories
- Free up disk space and resources
- Prevent potential mount conflicts

MANUAL CLEANUP (No):
- Skip automatic cleanup operations
- You will need to manually unmount images if needed
- May require manual cleanup later

Note: Cleanup operations are safe and will not affect your original WIM files.

Perform automatic cleanup?
"@, 
                                "Cleanup Mounted Images", 
                                [System.Windows.MessageBoxButton]::YesNo, 
                                [System.Windows.MessageBoxImage]::Question
                            )
                    
                            if ($cleanupChoice -eq [System.Windows.MessageBoxResult]::Yes) {
                                Write-ApplicationLog "Starting automatic cleanup of mounted images..." ([LogLevel]::Info)
                                Start-AsyncCleanup -MountDirectory $mountValidation.ResolvedPath
                            }
                            else {
                                Write-ApplicationLog "User skipped automatic cleanup - manual cleanup may be required" ([LogLevel]::Info)
                            }
                        }
                    }
            
                    # Reset application state
                    $script:ApplicationState.Reset()
                    $uiElements.StartButton.IsEnabled = $true
                    $uiElements.CancelButton.Content = "Cancel"
                    $uiElements.CancelButton.IsEnabled = $true
                    Update-ApplicationProgress 0.0 "Operation cancelled by user"
                    Write-ApplicationLog "Operation cancellation completed successfully" ([LogLevel]::Warning)
            
                }
                catch {
                    Write-ApplicationLog "Error during operation cancellation: $($_.Exception.Message)" ([LogLevel]::Error)
            
                    [System.Windows.MessageBox]::Show(
                        @"
CANCELLATION WARNING

Unable to completely cancel the operation: $($_.Exception.Message)

CURRENT STATUS:
- Some background processes may still be running
- Manual cleanup may be required
- Check Task Manager for lingering DISM processes

RECOMMENDED ACTIONS:
- Wait a few minutes for processes to complete naturally
- Check Task Manager for any remaining dism.exe processes
- Manually unmount any mounted images if needed
- Restart the application if necessary

If you continue to experience issues, consider restarting your computer.
"@, 
                        "Cancellation Warning", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Warning
                    )
                }
            }
            else {
                Write-ApplicationLog "User chose not to cancel the operation" ([LogLevel]::Info)
            }
        }
        else {
            # Handle application exit request
            $result = [System.Windows.MessageBox]::Show(
                @"
EXIT APPLICATION?

Are you sure you want to exit the WIM Driver Studio?

CURRENT STATUS:
- No operations are currently running
- All changes have been saved
- It is safe to exit the application

You can restart the application at any time to perform additional driver injections.
"@, 
                "Confirm Application Exit", 
                [System.Windows.MessageBoxButton]::YesNo, 
                [System.Windows.MessageBoxImage]::Question
            )
    
            if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                Write-ApplicationLog "User requested application exit" ([LogLevel]::Info)
                $window.Close()
            }
        }
    })

Write-Verbose "Simplified main process control handlers configured successfully"
#endregion

#region 16. Enhanced Asynchronous Cleanup Function
<#
.SYNOPSIS
    Provides asynchronous cleanup of mounted WIM images and temporary files.
    
.DESCRIPTION
    This region implements safe, non-blocking cleanup operations:
    - Asynchronous DISM unmount operations
    - Global mount point cleanup
    - Progress monitoring with timeout handling
    - Comprehensive error handling and reporting
#>

<#
.SYNOPSIS
    Starts asynchronous cleanup of mount directories and DISM operations.
    
.DESCRIPTION
    Performs safe, non-blocking cleanup with:
    - Background DISM unmount operations
    - Global mount point cleanup as fallback
    - Progress monitoring and timeout handling
    - Comprehensive error reporting
    - Resource management and disposal
    
.PARAMETER MountDirectory
    Path to the mount directory to clean up
    
.OUTPUTS
    Hashtable containing cleanup operation handles for monitoring
#>
function Start-AsyncCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MountDirectory
    )
    
    process {
        try {
            Write-ApplicationLog "Starting asynchronous cleanup for: $MountDirectory" ([LogLevel]::Info)
            
            # Create isolated runspace for cleanup operations
            $cleanupRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $cleanupRunspace.Open()
            
            # Set required variables in cleanup runspace
            $cleanupRunspace.SessionStateProxy.SetVariable("MountDir", $MountDirectory)
            $cleanupRunspace.SessionStateProxy.SetVariable("DismUnmountCommand", $script:Configuration.DismUnmountImage)
            $cleanupRunspace.SessionStateProxy.SetVariable("DismDiscardFlag", $script:Configuration.DismDiscardFlag)
            $cleanupRunspace.SessionStateProxy.SetVariable("DismCleanupCommand", $script:Configuration.DismCleanupMountpoints)
            $cleanupRunspace.SessionStateProxy.SetVariable("TimeoutMs", $script:Configuration.AsyncCleanupTimeoutMs)
            
            # Define comprehensive cleanup script with enhanced error handling
            $cleanupScript = {
                try {
                    Write-Verbose "Starting background cleanup operations"
                    
                    # Step 1: Attempt targeted unmount of specific directory
                    Write-Verbose "Attempting to unmount directory: $MountDir"
                    
                    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
                    $processInfo.FileName = "dism.exe"
                    # --- CORRECTED SECTION START ---
                    # Correctly format the arguments with the /MountDir flag
                    $processInfo.Arguments = "$DismUnmountCommand /MountDir:`"$MountDir`" $DismDiscardFlag"
                    # --- CORRECTED SECTION END ---
                    $processInfo.UseShellExecute = $false
                    $processInfo.CreateNoWindow = $true
                    $processInfo.RedirectStandardOutput = $true
                    $processInfo.RedirectStandardError = $true
                    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                    
                    $unmountSuccess = $false
                    try {
                        $process = [System.Diagnostics.Process]::Start($processInfo)
                        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
                        $stderrTask = $process.StandardError.ReadToEndAsync()
                        if ($process.WaitForExit($TimeoutMs)) {
                            $unmountSuccess = ($process.ExitCode -eq 0)
                            if ($unmountSuccess) {
                                Write-Verbose "Successfully unmounted directory: $MountDir"
                            }
                            else {
                                Write-Verbose "Unmount failed with exit code: $($process.ExitCode)"
                                $errorOutput = $stderrTask.Result
                                if (-not [string]::IsNullOrWhiteSpace($errorOutput)) {
                                    Write-Verbose "Unmount error output: $errorOutput"
                                }
                            }
                        }
                        else {
                            Write-Verbose "Unmount operation timed out"
                            try { $process.Kill() } catch { }
                        }
                        $process.Dispose()
                    }
                    catch {
                        Write-Verbose "Exception during unmount: $($_.Exception.Message)"
                    }
                    
                    # Step 2: Global cleanup attempt if specific unmount failed
                    if (-not $unmountSuccess) {
                        Write-Verbose "Attempting global mount point cleanup"
                        
                        $processInfo.Arguments = $DismCleanupCommand
                        try {
                            $globalProcess = [System.Diagnostics.Process]::Start($processInfo)
                            $globalStdoutTask = $globalProcess.StandardOutput.ReadToEndAsync()
                            $globalStderrTask = $globalProcess.StandardError.ReadToEndAsync()
                            if ($globalProcess.WaitForExit($TimeoutMs)) {
                                $globalSuccess = ($globalProcess.ExitCode -eq 0)
                                if ($globalSuccess) {
                                    Write-Verbose "Global cleanup completed successfully"
                                }
                                else {
                                    Write-Verbose "Global cleanup failed with exit code: $($globalProcess.ExitCode)"
                                }
                                $globalProcess.Dispose()
                                
                                return @{ 
                                    Success = $globalSuccess
                                    Message = if ($globalSuccess) { "Global cleanup successful" } else { "Global cleanup failed - manual cleanup may be required" }
                                    Method  = "Global"
                                }
                            }
                            else {
                                Write-Verbose "Global cleanup operation timed out"
                                try { $globalProcess.Kill() } catch { }
                                $globalProcess.Dispose()
                            }
                        }
                        catch {
                            Write-Verbose "Exception during global cleanup: $($_.Exception.Message)"
                        }
                        
                        return @{ 
                            Success = $false
                            Message = "Both targeted and global cleanup operations failed or timed out"
                            Method  = "Failed"
                        }
                    }
                    else {
                        return @{ 
                            Success = $true
                            Message = "Targeted directory unmount successful"
                            Method  = "Targeted"
                        }
                    }
                }
                catch {
                    Write-Verbose "Critical error during cleanup: $($_.Exception.Message)"
                    return @{ 
                        Success = $false
                        Message = "Critical cleanup error: $($_.Exception.Message)"
                        Method  = "Error"
                    }
                }
            }
            
            # Create PowerShell instance for cleanup execution
            $cleanupPowerShell = [System.Management.Automation.PowerShell]::Create()
            $cleanupPowerShell.Runspace = $cleanupRunspace
            $cleanupPowerShell.AddScript($cleanupScript)
            
            # Start cleanup operation and get async result
            $cleanupResult = $cleanupPowerShell.BeginInvoke()
            
            # Create timer for monitoring cleanup completion
            $cleanupTimer = [System.Windows.Threading.DispatcherTimer]::new()
            $cleanupTimer.Interval = [TimeSpan]::FromMilliseconds($script:Configuration.CleanupMonitorIntervalMs)
            
            $cleanupTimer.Add_Tick({
                    if ($cleanupResult.IsCompleted) {
                        $cleanupTimer.Stop()
                    
                        try {
                            $result = $cleanupPowerShell.EndInvoke($cleanupResult)
                        
                            if ($result.Success) {
                                Write-ApplicationLog "Async cleanup completed successfully: $($result.Message) (Method: $($result.Method))" ([LogLevel]::Success)
                            }
                            else {
                                Write-ApplicationLog "Async cleanup completed with warnings: $($result.Message)" ([LogLevel]::Warning)
                            }
                        }
                        catch {
                            Write-ApplicationLog "Async cleanup exception: $($_.Exception.Message)" ([LogLevel]::Warning)
                        }
                        finally {
                            # Comprehensive resource cleanup
                            try {
                                $cleanupPowerShell.Dispose()
                            }
                            catch { 
                                Write-Verbose "PowerShell disposal warning during cleanup: $($_.Exception.Message)"
                            }
                        
                            try {
                                $cleanupRunspace.Close()
                                $cleanupRunspace.Dispose()
                            }
                            catch { 
                                Write-Verbose "Runspace disposal warning during cleanup: $($_.Exception.Message)"
                            }
                        }
                    }
                })
            
            # Start monitoring timer
            $cleanupTimer.Start()
            
            Write-ApplicationLog "Asynchronous cleanup initiated with timeout of $($script:Configuration.AsyncCleanupTimeoutMs / 1000) seconds" ([LogLevel]::Info)
            
            # Return operation handles for external monitoring if needed
            return @{
                PowerShell = $cleanupPowerShell
                Runspace   = $cleanupRunspace
                Timer      = $cleanupTimer
                Result     = $cleanupResult
            }
        }
        catch {
            Write-ApplicationLog "Failed to start asynchronous cleanup: $($_.Exception.Message)" ([LogLevel]::Warning)
            
            # Cleanup any partially created resources
            if ($cleanupPowerShell) {
                try { $cleanupPowerShell.Dispose() } 
                catch { Write-Verbose "PowerShell disposal error: $($_.Exception.Message)" }
            }
            if ($cleanupRunspace) {
                try { 
                    $cleanupRunspace.Close()
                    $cleanupRunspace.Dispose() 
                } 
                catch { Write-Verbose "Runspace disposal error: $($_.Exception.Message)" }
            }
            
            return $null
        }
    }
}

Write-Verbose "Enhanced asynchronous cleanup function loaded successfully"
#endregion

#region 17. Enhanced Window Lifecycle Management
<#
.SYNOPSIS
    Comprehensive window lifecycle and application shutdown management.
    
.DESCRIPTION
    This region handles application shutdown scenarios:
    - Safe shutdown during active operations
    - Emergency cleanup and resource disposal
    - User confirmation for potentially destructive actions
    - Comprehensive resource cleanup and memory management
#>

# Enhanced Window Closing Handler with comprehensive cleanup and user protection
$window.Add_Closing({
        param($windowSender, $cancelEventArgs)
    
        try {
            Write-ApplicationLog "Application shutdown initiated" ([LogLevel]::Info)
        
            # Check if critical operations are in progress
            if ($script:ApplicationState.IsProcessing()) {
                Write-ApplicationLog "Active operation detected during shutdown request" ([LogLevel]::Warning)
            
                $result = [System.Windows.MessageBox]::Show(
                    @"
ACTIVE OPERATION IN PROGRESS

A driver injection process is currently running. Closing the application now may result in:

POTENTIAL ISSUES:
- Mounted WIM images left in inconsistent state
- Temporary files not properly cleaned up
- Background DISM processes continuing to run
- Potential system instability or resource leaks
- Loss of current operation progress

RECOMMENDED ACTION:
Cancel the current operation first using the 'Cancel Operation' button, then exit the application safely.

ALTERNATIVE ACTIONS:
- Wait for the current operation to complete naturally
- Use Task Manager to monitor and terminate processes if needed

Force close anyway? (NOT RECOMMENDED)
This will attempt emergency cleanup but may not be completely safe.
"@, 
                    "Active Operation - Unsafe Shutdown", 
                    [System.Windows.MessageBoxButton]::YesNo, 
                    [System.Windows.MessageBoxImage]::Warning
                )
            
                if ($result -eq [System.Windows.MessageBoxResult]::No) {
                    Write-ApplicationLog "User cancelled shutdown to avoid interrupting active operation" ([LogLevel]::Info)
                    $cancelEventArgs.Cancel = $true
                    return
                }
            
                Write-ApplicationLog "User confirmed force shutdown despite active operation" ([LogLevel]::Warning)
            
                # Enhanced emergency cleanup with comprehensive resource termination
                try {
                    Write-ApplicationLog "Performing emergency cleanup during forced shutdown..." ([LogLevel]::Warning)
                    Update-ApplicationProgress 0.0 "Emergency shutdown in progress..."
                
                    # Terminate active DISM processes
                    $currentProcess = $script:ApplicationState.GetCurrentProcess()
                    if ($currentProcess -and -not $currentProcess.HasExited) {
                        Write-ApplicationLog "Emergency termination of DISM process" ([LogLevel]::Warning)
                        try {
                            $currentProcess.Kill()
                            $currentProcess.WaitForExit(5000)  # Wait up to 5 seconds
                        }
                        catch {
                            Write-ApplicationLog "Error terminating DISM process: $($_.Exception.Message)" ([LogLevel]::Error)
                        }
                    }
                
                    # Stop PowerShell execution
                    $currentPowerShell = $script:ApplicationState.GetCurrentPowerShell()
                    if ($currentPowerShell) {
                        Write-ApplicationLog "Emergency termination of PowerShell execution" ([LogLevel]::Warning)
                        try {
                            $currentPowerShell.Stop()
                        }
                        catch {
                            Write-ApplicationLog "Error stopping PowerShell execution: $($_.Exception.Message)" ([LogLevel]::Error)
                        }
                    }
                
                    # Attempt emergency mount cleanup
                    $mountDir = $uiElements.MountDirTextBox.Text
                    if (-not [string]::IsNullOrWhiteSpace($mountDir)) {
                        $mountValidation = Test-SecurePath -Path $mountDir
                        if ($mountValidation.IsValid) {
                            Write-ApplicationLog "Attempting emergency mount directory cleanup" ([LogLevel]::Info)
                            try {
                                # Quick cleanup attempt without waiting for completion
                                Start-AsyncCleanup -MountDirectory $mountValidation.ResolvedPath | Out-Null
                            }
                            catch {
                                Write-ApplicationLog "Emergency mount cleanup failed: $($_.Exception.Message)" ([LogLevel]::Warning)
                            }
                        }
                    }
                
                    Write-ApplicationLog "Emergency cleanup completed - some manual cleanup may still be required" ([LogLevel]::Warning)
                }
                catch {
                    Write-ApplicationLog "Emergency cleanup failed: $($_.Exception.Message)" ([LogLevel]::Error)
                
                    # Show warning about potential system issues
                    [System.Windows.MessageBox]::Show(
                        @"
EMERGENCY CLEANUP WARNING

Unable to complete emergency cleanup: $($_.Exception.Message)

MANUAL CLEANUP MAY BE REQUIRED:
- Check Task Manager for lingering dism.exe processes
- Manually unmount any mounted WIM images using DISM
- Clean up temporary mount directories
- Run 'dism /cleanup-mountpoints' as administrator

COMMANDS FOR MANUAL CLEANUP:
1. Open Command Prompt as Administrator
2. Run: dism /cleanup-mountpoints
3. Check mount directory: $mountDir
4. Remove any remaining temporary files

Monitor system performance and restart if necessary.
"@, 
                        "Emergency Cleanup Warning", 
                        [System.Windows.MessageBoxButton]::OK, 
                        [System.Windows.MessageBoxImage]::Warning
                    )
                }
            }
        
            # Enhanced normal shutdown procedure
            try {
                Write-ApplicationLog "Performing normal application shutdown..." ([LogLevel]::Info)
            
                # Reset application state and clear references
                $script:ApplicationState.Reset()
            
                # Unregister any remaining event subscriptions
                $eventSub = $script:ApplicationState.GetEventSubscription()
                if ($eventSub) {
                    try {
                        Unregister-Event -SubscriptionId $eventSub.Id -Force -ErrorAction SilentlyContinue
                        Write-ApplicationLog "Event subscriptions cleaned up" ([LogLevel]::Info)
                    }
                    catch {
                        Write-Verbose "Event subscription cleanup warning: $($_.Exception.Message)"
                    }
                }
            
                # Clear UI references to prevent memory leaks
                $script:MainWindow = $null
            
                # Force garbage collection for clean shutdown
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                [System.GC]::Collect()
            
                Write-ApplicationLog "Application shutdown completed successfully" ([LogLevel]::Info)
            }
            catch {
                Write-ApplicationLog "Error during normal shutdown: $($_.Exception.Message)" ([LogLevel]::Warning)
            }
        }
        catch {
            Write-ApplicationLog "Critical error during application shutdown: $($_.Exception.Message)" ([LogLevel]::Error)
        
            # Ensure shutdown continues even on critical errors
            try {
                $script:ApplicationState.Reset()
                $script:MainWindow = $null
                [System.GC]::Collect()
            }
            catch { }
        }
    })

Write-Verbose "Enhanced window lifecycle management configured successfully"
#endregion

#region 18. Enhanced Application Initialization and Startup
<#
.SYNOPSIS
    Comprehensive application initialization with system validation and user guidance.
    
.DESCRIPTION
    This region handles the complete application startup sequence:
    - System requirements validation and reporting
    - Security privilege verification
    - DISM tool availability checking
    - User interface initialization
    - Comprehensive error handling and user guidance
    - Professional startup messaging and logging
#>

try {
    Write-ApplicationLog "WIM Driver Studio starting..." ([LogLevel]::Info)
    Write-ApplicationLog "Enhanced features: Thread-safe operations, optimized parallel processing, Windows 11 Fluent Design, comprehensive security validation" ([LogLevel]::Info)
    Write-ApplicationLog "PowerShell version: $($PSVersionTable.PSVersion)" ([LogLevel]::Info)
    Write-ApplicationLog "Operating system: $([System.Environment]::OSVersion.VersionString)" ([LogLevel]::Info)
    Write-ApplicationLog "Processor count: $([System.Environment]::ProcessorCount)" ([LogLevel]::Info)
    
    # Step 1: Enhanced security and system requirements validation
    Write-ApplicationLog "Performing comprehensive system validation..." ([LogLevel]::Info)
    
    $adminCheck = Test-EnhancedAdministratorPrivileges
    $dismCheck = Test-DismToolAvailability
    
    # Step 2: Update security status with detailed messaging and user guidance
    if (-not $adminCheck) {
        Write-ApplicationLog "Administrator privileges not available - running in demonstration mode" ([LogLevel]::Warning)
        
        # Update UI to reflect demonstration mode
        $uiElements.StartButton.IsEnabled = $false
        $uiElements.StartButton.ToolTip = "Administrator privileges required - restart as administrator to enable driver injection"
        $uiElements.SecurityStatusBlock.Text = "[!] Administrator privileges required"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(196, 43, 28))
        
        # Show comprehensive guidance dialog
        [System.Windows.MessageBox]::Show(
            @"
ADMINISTRATOR PRIVILEGES REQUIRED

Enhanced Administrator privileges are required for WIM driver injection operations.

CURRENT LIMITATIONS:
- WIM file mounting/unmounting operations disabled
- Driver injection into WIM images disabled  
- DISM command execution disabled
- Secure file system operations disabled

DEMONSTRATION MODE FEATURES:
+ Browse and select WIM files (validation only)
+ Browse and scan driver folders
+ View driver information and metadata
+ Test user interface functionality
+ Preview operation workflow

TO ENABLE FULL FUNCTIONALITY:
1. Close this application
2. Right-click on the application executable
3. Select 'Run as Administrator'
4. Confirm UAC prompt if displayed
5. Restart the application

SECURITY NOTICE:
Administrator privileges are required for:
- Mounting system images safely
- Modifying Windows boot environments
- Accessing protected system directories
- Executing DISM operations securely

The application will continue in demonstration mode for evaluation purposes.
"@, 
            "Administrator Privileges Required", 
            [System.Windows.MessageBoxButton]::OK, 
            [System.Windows.MessageBoxImage]::Warning
        )
    }
    else {
        Write-ApplicationLog "Enhanced administrator privileges confirmed" ([LogLevel]::Success)
        $uiElements.SecurityStatusBlock.Text = "[OK] Running with enhanced Administrator privileges"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
    }
    
    # Step 3: DISM tool validation with detailed error guidance
    if (-not $dismCheck) {
        Write-ApplicationLog "DISM tool not available - limited functionality mode" ([LogLevel]::Error)
        
        # Disable functionality that requires DISM
        $uiElements.StartButton.IsEnabled = $false
        $uiElements.StartButton.ToolTip = "DISM tool not available - install Windows ADK to enable driver injection"
        
        # Show comprehensive DISM installation guidance
        [System.Windows.MessageBox]::Show(
            @"
DISM TOOL NOT AVAILABLE

DISM (Deployment Image Servicing and Management) tool is required for WIM operations.

DISM IS REQUIRED FOR:
- Reading WIM file information and indexes
- Mounting and unmounting WIM images  
- Injecting drivers into mounted images
- Committing changes to WIM files
- Managing Windows image deployments

INSTALLATION OPTIONS:

OPTION 1 - Windows ADK (Recommended):
1. Download Windows Assessment and Deployment Kit (ADK)
2. Run the ADK installer
3. Select 'Deployment Tools' feature during installation
4. Complete installation and restart this application

OPTION 2 - Windows Feature (Windows 10/11):
1. Open 'Turn Windows features on or off'
2. Enable 'Windows Subsystem for Linux' (if available)
3. Install Windows ADK as backup method

OPTION 3 - Verify Installation:
1. Open Command Prompt as Administrator
2. Run: dism /?
3. If command not found, reinstall Windows ADK

DOWNLOAD LOCATION:
Visit Microsoft's official website to download the latest Windows ADK for your Windows version.

The application will run in limited demonstration mode without DISM functionality.
"@, 
            "DISM Tool Not Available", 
            [System.Windows.MessageBoxButton]::OK, 
            [System.Windows.MessageBoxImage]::Error
        )
    }
    else {
        Write-ApplicationLog "DISM tool verified and available" ([LogLevel]::Success)
    }
    
    # Step 4: Final status update with comprehensive system readiness assessment
    if ($adminCheck -and $dismCheck) {
        $uiElements.SecurityStatusBlock.Text = "Ready for driver injection"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(16, 124, 16))
        Write-ApplicationLog "All security and system checks passed - application fully operational" ([LogLevel]::Success)
    }
    elseif ($adminCheck -and -not $dismCheck) {
        $uiElements.SecurityStatusBlock.Text = "[!] DISM tool required for full functionality"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(255, 140, 0))
        Write-ApplicationLog "Administrator privileges available but DISM tool missing" ([LogLevel]::Warning)
    }
    elseif (-not $adminCheck -and $dismCheck) {
        $uiElements.SecurityStatusBlock.Text = "[!] Administrator privileges required"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(196, 43, 28))
        Write-ApplicationLog "DISM tool available but administrator privileges missing" ([LogLevel]::Warning)
    }
    else {
        $uiElements.SecurityStatusBlock.Text = "[X] Administrator privileges and DISM tool required"
        $uiElements.SecurityStatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(196, 43, 28))
        Write-ApplicationLog "Both administrator privileges and DISM tool missing" ([LogLevel]::Error)
    }
    
    # Step 5: Set initial workflow step and finalize UI state
    Update-WorkflowStep -Step ([WorkflowStep]::SelectWim)
    
    # Step 6: Enhanced startup logging with system information
    Write-ApplicationLog "UI initialization completed successfully" ([LogLevel]::Success)
    Write-ApplicationLog "Thread-safe state management initialized" ([LogLevel]::Info)
    Write-ApplicationLog "Windows 11 Fluent Design interface ready" ([LogLevel]::Info)
    Write-ApplicationLog "Security validation completed" ([LogLevel]::Info)
    Write-ApplicationLog "Performance optimization enabled (parallel processing: $($script:Configuration.MaxParallelThreads) threads)" ([LogLevel]::Info)
    Write-ApplicationLog "Application ready for user interaction" ([LogLevel]::Success)
    
    # Step 7: Show the main window with enhanced error handling
    Write-ApplicationLog "Displaying main application window..." ([LogLevel]::Info)
    Write-ApplicationLog "Application startup completed successfully" ([LogLevel]::Success)
    
    # Final garbage collection before showing window
    [System.GC]::Collect()
    
    # Show the main window and enter message loop
    $window.ShowDialog() | Out-Null
}
catch [System.Exception] {
    $errorMessage = "Application failed to start: $($_.Exception.Message)"
    Write-ApplicationLog $errorMessage ([LogLevel]::Error)
    
    # Show comprehensive error dialog with troubleshooting guidance
    [System.Windows.MessageBox]::Show(
        @"
CRITICAL INITIALIZATION ERROR

The application failed to start due to a critical error:

ERROR DETAILS:
$($_.Exception.Message)

POSSIBLE CAUSES:
- Missing or corrupted .NET Framework components
- Insufficient system resources (memory/CPU)
- Windows PowerShell execution policy restrictions
- Antivirus software interference
- System file corruption or instability
- Missing Windows Presentation Foundation (WPF) components

TROUBLESHOOTING STEPS:
1. Restart your computer and try again
2. Run Windows Update to install latest components
3. Temporarily disable antivirus real-time protection
4. Check PowerShell execution policy (Run: Get-ExecutionPolicy)
5. Verify .NET Framework 4.7.2 or later is installed
6. Run System File Checker (sfc /scannow)
7. Check Windows Event Viewer for additional error details

ADVANCED TROUBLESHOOTING:
- Install latest Windows PowerShell updates
- Verify WPF components are installed
- Check system compatibility with Windows 10/11
- Contact system administrator for enterprise environments

STACK TRACE:
$($_.Exception.StackTrace)

If the problem persists, contact technical support with this error information.
"@, 
        "Critical Initialization Error", 
        [System.Windows.MessageBoxButton]::OK, 
        [System.Windows.MessageBoxImage]::Error
    )
    
    Write-Error "Critical startup error: $($_.Exception.Message)"
    exit 1
}
finally {
    # Step 8: Final cleanup and resource management
    try {
        Write-ApplicationLog "Application shutdown sequence initiated" ([LogLevel]::Info)
        
        # Reset application state
        if ($script:ApplicationState) {
            $script:ApplicationState.Reset()
        }
        
        # Clear global references
        $script:MainWindow = $null
        
        # Restore original progress preference
        if ($originalProgressPreference) {
            $ProgressPreference = $originalProgressPreference
        }
        
        # Final garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        
        Write-ApplicationLog "Application shutdown completed successfully" ([LogLevel]::Info)
        Write-ApplicationLog "All resources cleaned up properly" ([LogLevel]::Info)
        Write-ApplicationLog "Thank you for using WIM Driver Studio" ([LogLevel]::Info)
    }
    catch {
        Write-Verbose "Final cleanup warning: $($_.Exception.Message)"
    }
}

Write-Verbose "Enhanced application initialization and startup completed successfully"
#endregion