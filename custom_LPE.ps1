Write-Output "`n==============================="
Write-Output " Unquoted Service Path Review"
Write-Output "===============================`n"


$UnquotedServicePaths = Get-CimInstance Win32_Service | ForEach-Object {

    $service = $_
    $path = $service.PathName

    if ($path -match '^(?<exe>.+?\.exe)') {

        $exe = $matches.exe

        if (-not $exe.StartsWith('"') -and
            $exe -match '\s' -and
            $exe -notlike 'C:\Windows\*') {

            $directory = Split-Path $exe

            try {

                $acl = Get-Acl $directory

                $writable = $acl.Access | Where-Object {
                    $_.IdentityReference -match 'Users|Authenticated Users|Everyone' -and
                    (
                        $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|CreateFiles'
                    ) -and
                    $_.AccessControlType -eq 'Allow'
                }


                [PSCustomObject]@{
                    Service     = $service.Name
                    DisplayName = $service.DisplayName
                    Directory   = $directory
                    Writable    = if ($writable) { "YES" } else { "No" }
                    Path        = $path
                }

            }
            catch {

                [PSCustomObject]@{
                    Service     = $service.Name
                    DisplayName = $service.DisplayName
                    Directory   = $directory
                    Writable    = "Unable to determine"
                    Path        = $path
                }
            }
        }
    }
}


# Results summary

if ($UnquotedServicePaths) {

    Write-Output "[!] Unquoted service paths identified:`n"

    $UnquotedServicePaths |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] No unquoted service paths identified."

}


Write-Output "`n===================================="
Write-Output " Modifiable Service File Assessment"
Write-Output "====================================`n"


$LowPrivilegeUsers = @(
    "Everyone",
    "BUILTIN\Users",
    "NT AUTHORITY\Authenticated Users",
    "Authenticated Users"
)


$results = foreach ($service in Get-CimInstance Win32_Service) {

    $path = $service.PathName

    # Skip services without a path
    if ([string]::IsNullOrWhiteSpace($path)) {
        continue
    }

    # Remove quotes and arguments
    $exePath = $path -replace '^"|"$',''

    if ($exePath -match "\.exe") {
        $exePath = $exePath.Substring(0, $exePath.ToLower().IndexOf(".exe") + 4)
    }
    else {
        continue
    }


    # Check if executable exists
    if (-not (Test-Path $exePath)) {
        continue
    }


    try {

        $acl = Get-Acl $exePath -ErrorAction Stop

        foreach ($entry in $acl.Access) {

            if ($LowPrivilegeUsers -contains $entry.IdentityReference.Value) {

                if (
                    $entry.FileSystemRights -match "Write" -or
                    $entry.FileSystemRights -match "Modify" -or
                    $entry.FileSystemRights -match "FullControl"
                ) {

                    [PSCustomObject]@{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        StartName   = $service.StartName
                        State       = $service.State
                        BinaryPath  = $exePath
                        Identity    = $entry.IdentityReference
                        Rights      = $entry.FileSystemRights
                    }
                }
            }
        }

    }
    catch {
        continue
    }
}


if ($results) {

    Write-Output "[!] Modifiable service files identified:`n"

    $results |
        Sort-Object ServiceName |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] No modifiable service files identified.`n"

}


Write-Output "`n==============================="
Write-Output " Modifiable Services Review"
Write-Output "===============================`n"


$ModifiableServices = Get-CimInstance Win32_Service | ForEach-Object {

    $service = $_

    try {

        # Get service security descriptor
        $sd = Invoke-CimMethod `
            -InputObject $service `
            -MethodName GetSecurityDescriptor `
            -ErrorAction Stop

        foreach ($ace in $sd.Descriptor.DACL) {

            $rights = $ace.AccessMask

            # Check for potentially dangerous service permissions
            if (
                ($rights -band 0x0002) -or   # SERVICE_CHANGE_CONFIG
                ($rights -band 0x00040000) -or # WRITE_DAC
                ($rights -band 0x00080000) -or # WRITE_OWNER
                ($rights -band 0x10000000) -or # GENERIC_ALL
                ($rights -band 0x40000000)    # GENERIC_WRITE
            ) {

                # Resolve SID
                try {
                    $identity = (New-Object System.Security.Principal.SecurityIdentifier($ace.Trustee.SID)).Translate([System.Security.Principal.NTAccount])
                }
                catch {
                    $identity = $ace.Trustee.SID
                }


                # Only report common low privilege groups
                if (
                    $identity -match "Everyone|Users|Authenticated Users|BUILTIN\\Users"
                ) {

                    [PSCustomObject]@{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        StartName   = $service.StartName
                        State       = $service.State
                        Identity    = $identity
                        AccessMask  = ('0x{0:X}' -f $rights)
                        Path        = $service.PathName
                    }
                }
            }
        }

    }
    catch {
        # Ignore services where security descriptor cannot be queried
    }

}


# Results Summary

if ($ModifiableServices) {

    Write-Output "[!] Modifiable services identified:`n"

    $ModifiableServices |
        Sort-Object ServiceName |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] No modifiable services identified.`n"

}


Write-Output "`n====================================="
Write-Output " DLL Hijacking Vulnerability Review"
Write-Output "=====================================`n"


$DLLHijackFindings = foreach ($process in Get-Process) {

    try {

        # Get loaded modules for each process
        foreach ($module in $process.Modules) {

            $dllPath = $module.FileName

            if (-not $dllPath) {
                continue
            }

            $directory = Split-Path $dllPath


            # Skip Windows protected locations
            if (
                $directory -like "C:\Windows\System32*" -or
                $directory -like "C:\Windows\WinSxS*"
            ) {
                continue
            }


            try {

                $acl = Get-Acl $directory

                $writable = $acl.Access | Where-Object {

                    $_.IdentityReference -match `
                    "Everyone|Users|Authenticated Users|BUILTIN\\Users" -and

                    $_.AccessControlType -eq "Allow" -and

                    (
                        $_.FileSystemRights.ToString() -match `
                        "Write|Modify|FullControl|CreateFiles"
                    )
                }


                if ($writable) {

                    [PSCustomObject]@{
                        Process       = $process.ProcessName
                        PID           = $process.Id
                        User          = (Get-Process -Id $process.Id -IncludeUserName -ErrorAction SilentlyContinue).UserName
                        DLL           = Split-Path $dllPath -Leaf
                        DLLPath       = $dllPath
                        WritableBy    = ($writable.IdentityReference -join ", ")
                        Permissions   = ($writable.FileSystemRights -join ", ")
                    }

                }

            }
            catch {
                continue
            }

        }

    }
    catch {
        # Access denied / protected process
        continue
    }

}


# Results Summary

if ($DLLHijackFindings) {

    Write-Output "[!] Potential DLL Hijacking opportunities identified:`n"

    $DLLHijackFindings |
        Sort-Object Process |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] No obvious DLL hijacking opportunities identified.`n"

}


Write-Output "`n====================================="
Write-Output " PATH DLL Hijacking Review"
Write-Output "=====================================`n"


$PathHijackFindings = @()


# Collect System and User PATH variables

$Paths = @()

$Paths += [Environment]::GetEnvironmentVariable(
    "Path",
    "Machine"
).Split(";")

$Paths += [Environment]::GetEnvironmentVariable(
    "Path",
    "User"
).Split(";")


foreach ($path in $Paths) {

    # Remove whitespace
    $path = $path.Trim()

    # Skip empty paths
    if ([string]::IsNullOrWhiteSpace($path)) {
        continue
    }


    # Expand environment variables
    $path = [Environment]::ExpandEnvironmentVariables($path)


    # Check directory exists
    if (-not (Test-Path $path -PathType Container)) {
        continue
    }


    try {

        $acl = Get-Acl $path


        $writable = $acl.Access | Where-Object {

            $_.IdentityReference -match `
            "Everyone|Users|Authenticated Users|BUILTIN\\Users" -and

            $_.AccessControlType -eq "Allow" -and

            (
                $_.FileSystemRights.ToString() -match `
                "Write|Modify|FullControl|CreateFiles"
            )
        }


        if ($writable) {

            $PathHijackFindings += [PSCustomObject]@{

                Path          = $path
                Identity      = ($writable.IdentityReference -join ", ")
                Permissions   = ($writable.FileSystemRights -join ", ")
                Source        = if (
                                    $Paths.IndexOf($path) -eq 0
                                ) {
                                    "System/User PATH"
                                }
                                else {
                                    "PATH"
                                }

            }

        }

    }
    catch {

        continue

    }

}


# Results Summary

if ($PathHijackFindings) {

    Write-Output "[!] Writable PATH directories identified:`n"

    $PathHijackFindings |
        Sort-Object Path |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] No writable PATH directories identified.`n"

}

Write-Output "`n====================================="
Write-Output " AlwaysInstallElevated Review"
Write-Output "=====================================`n"


$AlwaysInstallElevated = $false


$HKLM = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -Name AlwaysInstallElevated `
    -ErrorAction SilentlyContinue


$HKCU = Get-ItemProperty `
    -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -Name AlwaysInstallElevated `
    -ErrorAction SilentlyContinue



if (
    $HKLM.AlwaysInstallElevated -eq 1 -and
    $HKCU.AlwaysInstallElevated -eq 1
) {

    $AlwaysInstallElevated = [PSCustomObject]@{

        HKLM_Value = $HKLM.AlwaysInstallElevated
        HKCU_Value = $HKCU.AlwaysInstallElevated
        Status     = "Enabled"

    }

}



if ($AlwaysInstallElevated) {

    Write-Output "[!] AlwaysInstallElevated is enabled:`n"

    $AlwaysInstallElevated |
        Format-Table -AutoSize

}
else {

    Write-Output "[+] AlwaysInstallElevated is not enabled.`n"

}

Write-Output "`n====================================="
Write-Output " Registry AutoLogon Review"
Write-Output "=====================================`n"


$AutoLogon = Get-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ErrorAction SilentlyContinue



if (
    $AutoLogon.AutoAdminLogon -eq "1" -and
    $AutoLogon.DefaultUserName
) {


    $AutoLogonFinding = [PSCustomObject]@{

        AutoAdminLogon = $AutoLogon.AutoAdminLogon
        Username       = $AutoLogon.DefaultUserName
        Domain         = $AutoLogon.DefaultDomainName
        Password       = $AutoLogon.DefaultPassword

    }


}



if ($AutoLogonFinding) {


    Write-Output "[!] AutoLogon credentials identified:`n"


    $AutoLogonFinding |
        Format-Table -AutoSize


}
else {

    Write-Output "[+] No AutoLogon credentials identified.`n"

}


Write-Output "`n====================================="
Write-Output " Modifiable Registry AutoRun Review"
Write-Output "=====================================`n"



$RegistryAutoRunFindings = @()


$RunKeys = @(

"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",

"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",

"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",

"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"

)



foreach ($key in $RunKeys) {


    if (Test-Path $key) {


        $registry = Get-ItemProperty -Path $key


        foreach ($property in $registry.PSObject.Properties) {


            if (
                $property.Name -notmatch "^PS"
            ) {


                $path = $property.Value


                # Extract executable path

                if ($path -match '^(?:"([^"]+)"|([^\s]+))') {

                    $exe = $matches[1]

                    if (-not $exe) {
                        $exe = $matches[2]
                    }



                    if (Test-Path $exe) {


                        try {


                            $acl = Get-Acl $exe


                            $writable = $acl.Access | Where-Object {

                                $_.IdentityReference -match `
                                "Everyone|Users|Authenticated Users|BUILTIN\\Users" -and

                                $_.AccessControlType -eq "Allow" -and

                                $_.FileSystemRights.ToString() -match `
                                "Write|Modify|FullControl"

                            }



                            if ($writable) {


                                $RegistryAutoRunFindings += [PSCustomObject]@{

                                    RegistryKey = $key

                                    Entry       = $property.Name

                                    Executable  = $exe

                                    Identity    = $writable.IdentityReference

                                    Permissions = $writable.FileSystemRights

                                }


                            }


                        }
                        catch {

                        }

                    }

                }

            }

        }

    }

}



if ($RegistryAutoRunFindings) {


    Write-Output "[!] Modifiable Registry AutoRun entries identified:`n"


    $RegistryAutoRunFindings |
        Format-Table -AutoSize


}
else {

    Write-Output "[+] No modifiable Registry AutoRun entries identified.`n"

}


Write-Output "`n====================================="
Write-Output " Unattended Installation File Review"
Write-Output "=====================================`n"


$UnattendedFiles = @()


$SearchLocations = @(

    "C:\sysprep\sysprep.xml",

    "C:\sysprep\sysprep.inf",

    "C:\sysprep.inf",

    "$env:windir\Panther\Unattended.xml",

    "$env:windir\Panther\Unattend\Unattended.xml",

    "$env:windir\Panther\Unattend.xml",

    "$env:windir\Panther\Unattend\Unattend.xml",

    "$env:windir\System32\Sysprep\unattend.xml",

    "$env:windir\System32\Sysprep\Panther\unattend.xml"

)



foreach ($file in $SearchLocations) {


    if (Test-Path $file) {


        try {


            $content = Get-Content $file -ErrorAction SilentlyContinue


            $SensitiveData = $false


            if (
                $content -match "Password" -or
                $content -match "Administrator" -or
                $content -match "DomainPassword" -or
                $content -match "Credentials"
            ) {

                $SensitiveData = $true

            }



            $UnattendedFiles += [PSCustomObject]@{

                FilePath       = $file

                Contains       = if ($SensitiveData) {
                                    "Potential credentials identified"
                                }
                                else {
                                    "No obvious credentials identified"
                                }

                LastModified   = (Get-Item $file).LastWriteTime

            }


        }
        catch {


            $UnattendedFiles += [PSCustomObject]@{

                FilePath       = $file

                Contains       = "Unable to read file"

                LastModified   = ""

            }

        }

    }

}



if ($UnattendedFiles) {


    Write-Output "[!] Unattended installation files identified:`n"


    $UnattendedFiles |
        Format-Table -AutoSize


}
else {


    Write-Output "[+] No unattended installation files identified.`n"

}


Write-Output "`n====================================="
Write-Output " IIS Application Host Credential Review"
Write-Output "=====================================`n"



$IISCredentials = @()



# Check if IIS appcmd exists

$AppCmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"


if (Test-Path $AppCmd) {


    #
    # Check Application Pools
    #

    $AppPools = & $AppCmd list apppools /text:name


    foreach ($pool in $AppPools) {


        $username = & $AppCmd list apppool "$pool" /text:processmodel.username

        $password = & $AppCmd list apppool "$pool" /text:processmodel.password



        if (
            $password -and
            $password -notmatch "^\s*$"
        ) {


            $IISCredentials += [PSCustomObject]@{

                Type        = "Application Pool"

                Name        = $pool

                Username    = $username

                Password    = $password

                Location    = "IIS Application Pool"

            }

        }

    }



    #
    # Check Virtual Directories
    #

    $VirtualDirs = & $AppCmd list vdir /text:vdir.name


    foreach ($vdir in $VirtualDirs) {


        $username = & $AppCmd list vdir "$vdir" /text:userName

        $password = & $AppCmd list vdir "$vdir" /text:password



        if (
            $password -and
            $password -notmatch "^\s*$"
        ) {


            $IISCredentials += [PSCustomObject]@{

                Type        = "Virtual Directory"

                Name        = $vdir

                Username    = $username

                Password    = $password

                Location    = "IIS Virtual Directory"

            }

        }

    }


}
else {


    Write-Output "[+] IIS is not installed or appcmd.exe was not found."

}



#
# Results Summary
#

if ($IISCredentials) {


    Write-Output "[!] IIS stored credentials identified:`n"


    $IISCredentials |
        Format-Table -AutoSize


}
else {


    Write-Output "[+] No IIS stored credentials identified.`n"

}
