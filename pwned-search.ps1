$string = Read-Host -Prompt 'Password to check'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($string)
$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$data = $sha1.ComputeHash($bytes)
$result = ($data | ForEach-Object ToString X2) -join ''
$result = $result.ToUpper()
$head = $result.Substring(0,5)
$tail = $result.Substring(5)

[Net.ServicePointManager]::SecurityProtocol = "TLS12, TLS11, TLS, SSL3"
$request = [System.Net.WebRequest]::Create("https://api.pwnedpasswords.com/range/" + $head)
$reader = New-Object System.IO.StreamReader(($request.GetResponse()).GetResponseStream())

$found = 0
while (($line = $reader.ReadLine()) -ne $null) {
    if ($line.Split(':')[0] -eq $tail) {
        Write-Host "That password has been compromised."
        $found = 1
        break
    }
}
if ($found -eq 0) { Write-Host "That password was not found." }
