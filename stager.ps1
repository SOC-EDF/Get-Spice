$source = 'http://192.168.1.1/ORC/get-spice.zip'
$temp =  'C:\Windows\Temp\'
$filename = 'get-spice.zip'
$script = $filename.Split('.')[0]
$FileName = "$temp$filename"

# Checking NT version in order to choose the right downloading method
if ([System.Environment]::OSVersion.Version.Major -eq 10) {
    $webclient = new-object System.Net.WebClient
    $credCache = new-object System.Net.CredentialCache
    $creds = new-object System.Net.NetworkCredential("username","password")
    $credCache.Add($source, "Basic", $creds)
    $webclient.Credentials = $credCache

    $Zip = $webclient.DownloadData($source)

    [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
    $entry = (New-Object System.IO.Compression.ZipArchive(New-Object System.IO.MemoryStream ( , $Zip))).GetEntry('get-spice.ps1')
    $b = [byte[]]::new($entry.Length)
    $entry.Open().Read($b, 0, $b.Length)
    $Code = [System.Text.Encoding]::UTF8.GetString($b)

    Invoke-Expression $Code
}

else {
        $webclient = new-object System.Net.WebClient
        $credCache = new-object System.Net.CredentialCache
        $creds = new-object System.Net.NetworkCredential("username","password")
        $credCache.Add($source, "Basic", $creds)
        $webclient.Credentials = $credCache
    
        $webclient.DownloadFile("$source", "$FileName")
        $shell_app = new-object -com shell.application
        $zip_file = $shell_app.namespace($FileName)
        $destination = $shell_app.namespace($temp)
        $destination.Copyhere($zip_file.items(), 0x14)
        Invoke-Expression -Command "$temp$script.ps1"
        Remove-Item $FileName
        Remove-Item "$temp$script.ps1"
}
