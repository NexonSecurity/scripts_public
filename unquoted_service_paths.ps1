Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and 
    $_.PathName.TrimStart() -notlike '"*' -and 
    ($_.PathName -imatch '^\\s*(?<bin>.+?\\.exe)') -and 
    ($Matches['bin'] -match '\\s') -and 
    ($Matches['bin'] -notmatch '(?i)^%SystemRoot%\\\\|^C:\\\\Windows\\\\')
} | Select-Object Name, StartMode, PathName | Format-Table -AutoSize   
