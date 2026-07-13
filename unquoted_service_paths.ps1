Get-CimInstance Win32_Service | ForEach-Object {

    $path = $_.PathName

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
                    Service     = $_.Name
                    Directory   = $directory
                    Writable    = if ($writable) { "YES" } else { "No" }
                    Path        = $path
                }

            } catch {
                [PSCustomObject]@{
                    Service     = $_.Name
                    Directory   = $directory
                    Writable    = "Unable to determine"
                    Path        = $path
                }
            }
        }
    }
} | Format-Table -AutoSize
