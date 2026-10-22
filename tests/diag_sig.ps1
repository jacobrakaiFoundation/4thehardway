# Temporary diagnostic: why does the PowerShell scanner miss some signature blocks on Windows?
$ErrorActionPreference = 'Continue'
"PS $($PSVersionTable.PSVersion)  .NET $([Environment]::Version)"
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)
"Latin1 type: $($Latin1.GetType().FullName) cp=$($Latin1.CodePage)"
function Hex([string]$t) { (($t.ToCharArray() | ForEach-Object { '{0:X2}' -f [int]$_ }) -join ' ') }
$files = @(foreach ($d in @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ConfigDefender", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ConfigDefenderPerformance")) {
    Get-ChildItem -LiteralPath $d -File | Where-Object { @('.psd1', '.psm1', '.ps1xml') -contains $_.Extension } })
"files: $($files.Count)"
foreach ($f in $files) {
    $b = [System.IO.File]::ReadAllBytes($f.FullName)
    $s = $Latin1.GetString($b)
    "== $($f.FullName) bytes=$($b.Length) chars=$($s.Length) head=$([BitConverter]::ToString($b, 0, [Math]::Min(8, $b.Length)))"
    $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName
    "   authenticode: $($sig.Status) $($sig.SignatureType) $($sig.SignerCertificate.Thumbprint)"
    foreach ($pat in 'SIG # Begin signature block', 'SIG # End signature block') {
        $i = 0
        while (($i = $s.IndexOf($pat, $i, [StringComparison]::Ordinal)) -ge 0) {
            $st = [Math]::Max(0, $i - 16)
            "   '$pat' at $i  before: $(Hex $s.Substring($st, $i - $st))  after: $(Hex $s.Substring($i + $pat.Length, [Math]::Min(12, $s.Length - $i - $pat.Length)))"
            $i++
        }
    }
    "   IndexOf Ordinal = $($s.IndexOf('SIG # Begin signature block', [StringComparison]::Ordinal))  IndexOf default = $($s.IndexOf('SIG # Begin signature block'))"
    $u16 = $s.IndexOf($Latin1.GetString([System.Text.Encoding]::Unicode.GetBytes('SIG # Begin signature block')), [StringComparison]::Ordinal)
    "   utf16 marker at $u16"
    foreach ($pair in @(@('new', 'SIG # Begin signature block([\s\S]{20,400000}?)SIG # End signature block'), @('old', '# SIG # Begin signature block([\s\S]{20,400000}?)# SIG # End signature block'))) {
        $ms = [regex]::Matches($s, $pair[1])
        "   $($pair[0]) regex: $($ms.Count) match(es)"
        foreach ($m in $ms) {
            $body = $m.Groups[1].Value
            if ($pair[0] -eq 'old') { $body = [regex]::Replace($body, '(?m)^#\s?', '') }
            $c1 = [regex]::Replace($body, '\\[rn]', '')
            $clean = [regex]::Replace($c1, '[^A-Za-z0-9+/=]', '')
            $junk = @([regex]::Matches($body, '[^A-Za-z0-9+/=]') | ForEach-Object { [int][char]$_.Value } | Sort-Object -Unique)
            "     at $($m.Index) body=$($body.Length) afterBackslashRN=$($c1.Length) clean=$($clean.Length) mod4=$($clean.Length % 4) firstEq=$($clean.IndexOf('=')) junk=[$((($junk | ForEach-Object { '{0:X2}' -f $_ }) -join ' '))]"
            "     clean head: $($clean.Substring(0, [Math]::Min(40, $clean.Length)))  tail: $($clean.Substring([Math]::Max(0, $clean.Length - 40)))"
            $bs = [regex]::Matches($body, '\\[rn]')
            if ($bs.Count) { "     backslash-r/n sequences: $($bs.Count), first at $($bs[0].Index): $(Hex $body.Substring([Math]::Max(0, $bs[0].Index - 8), 16))" }
            try {
                $r = [Convert]::FromBase64String($clean + ('=' * ((4 - ($clean.Length % 4)) % 4)))
                "     decoded $($r.Length) bytes"
            } catch { "     decode error: $($_.Exception.Message)" }
        }
    }
    $exe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
    "   scanner -ListCerts ($exe):"
    $out = & $exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\..\Scan-EmudhraRevoked.ps1" -ListCerts -Path $f.FullName 2>&1
    $txt = ($out | Out-String)
    try { $j = $txt | ConvertFrom-Json; foreach ($x in @($j)) { "     $($x.sha1) $($x.found_as) $($x.container)" } } catch { "     (not JSON) $($txt.Substring(0, [Math]::Min(800, $txt.Length)))" }
}
