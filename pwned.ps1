Write-Host 'Checks first 5 characters of the SHA1 hash against haveibeenpwned.com API.'
Write-Host 'Enter an empty password or close the window to exit.'

while ($true) {
    $string = Read-Host -Prompt "`nPassword to check"
    
    if (-not $string) {
        Write-Host 'No password entered. Exiting..'
        exit
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
    $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $data = $sha1.ComputeHash($bytes)
    $result = ($data | ForEach-Object ToString X2) -join ''
    $head = $result.Substring(0,5)
    $tail = $result.Substring(5)

    [Net.ServicePointManager]::SecurityProtocol = "TLS12, TLS11, TLS, SSL3"
    $request = [System.Net.WebRequest]::Create("https://api.pwnedpasswords.com/range/" + $head)
    $reader = New-Object System.IO.StreamReader(($request.GetResponse()).GetResponseStream())

    $found = 0
    while ($null -ne ($line = $reader.ReadLine())) {
        if (($split = $line.Split(':'))[0] -eq $tail) {
            Write-Host "That password has been compromised. Occurrences:" $split[1]
            $found = 1
            break
        }
    }
    if ($found -eq 0) { Write-Host "That password was not found." }

    $reader.Close()
}
