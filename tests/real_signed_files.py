#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real-world check: the scanner must extract the signer certificate from files that are really signed,
as identified by the operating system's own signature tools (not by this project's code).

  Windows : signed .msi (C:\\Windows\\Installer), .exe/.dll, PowerShell files (.ps1/.psm1/.psd1/.ps1xml, and .cdxml/.mof
            when present) and Windows Script Host files (.vbs/.wsf, when present) with EMBEDDED Authenticode
            signatures; signer thumbprint from Get-AuthenticodeSignature. Each file is copied first and both the
            OS tool and the scanner read the copy, so an update replacing the file mid-test cannot cause a mismatch.
            With E2E_ALLOW_STORE_CHANGES=1, also .ps1/.vbs/.vbe/.js/.wsf/.cdxml/.mof files that Windows signs during the test
            with a throwaway self-signed certificate, so the formats Windows writes are checked.
  macOS   : Apple-signed Mach-O system binaries; signer from `codesign --extract-certificates`
  Linux   : a JAR signed during the test with keytool + jarsigner

usage: real_signed_files.py --scanner python|powershell|pwsh [--require-msi]
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

WINDOWS_INVENTORY = r"""
$ErrorActionPreference = 'SilentlyContinue'
$want = @{ msi = 4; pe = 6; script = 4; cdxml = 2; mof = 2; wsh = 3 }
$got = @{ msi = 0; pe = 0; script = 0; cdxml = 0; mof = 0; wsh = 0 }
$res = New-Object System.Collections.ArrayList
function Try-Add($f, $kind) {
    if ($got[$kind] -ge $want[$kind]) { return }
    if ($f.Length -gt 256MB) { return }   # Scan-EmudhraRevoked.ps1 skips files over -MaxSizeMB (default 256)
    $s = Get-AuthenticodeSignature -LiteralPath $f.FullName
    if ($null -eq $s -or $s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate) { return }
    if ($s.PSObject.Properties['SignatureType'] -and [string]$s.SignatureType -ne 'Authenticode') { return }  # embedded only, not catalog
    # Test a private copy. System files can be replaced while the test runs (Defender platform updates swap
    # its own PowerShell modules for versions with a different signer), which would compare two different files.
    $dir = Join-Path $env:SIGNED_FILES_WORK ('f' + $res.Count)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $copy = Join-Path $dir $f.Name
    Copy-Item -LiteralPath $f.FullName -Destination $copy
    $s = Get-AuthenticodeSignature -LiteralPath $copy
    if ($null -eq $s -or $s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate) { return }
    [void]$res.Add([ordered]@{ path = $copy; original = $f.FullName; kind = $kind; thumbprint = $s.SignerCertificate.Thumbprint.ToLower(); subject = $s.SignerCertificate.Subject })
    $got[$kind]++
}
Get-ChildItem -LiteralPath "$env:SystemRoot\Installer" -Filter *.msi -File | Select-Object -First 200 | ForEach-Object { Try-Add $_ 'msi' }
foreach ($d in @("$env:ProgramFiles\PowerShell\7", "$env:ProgramFiles\Git\cmd", "$env:ProgramFiles\Git\mingw64\bin", "$env:SystemRoot\System32")) {
    if (Test-Path -LiteralPath $d) { Get-ChildItem -Path "$d\*" -Include *.exe, *.dll -File | Select-Object -First 150 | ForEach-Object { Try-Add $_ 'pe' } }
}
# Defender's modules stay in: they are real embedded-signed .psm1 and .ps1xml files, and the Defender platform updates
# that rewrite them in place cannot affect the private copies tested here.
Get-ChildItem -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0" -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.ps1xml, *.cdxml, *.mof |
    Select-Object -First 3000 | ForEach-Object {
        $x = $_.Extension.ToLowerInvariant()
        if ($x -eq '.cdxml') { Try-Add $_ 'cdxml' } elseif ($x -eq '.mof') { Try-Add $_ 'mof' } else { Try-Add $_ 'script' }
    }
foreach ($d in @("$env:SystemRoot\System32", "$env:SystemRoot\System32\Printing_Admin_Scripts\en-US")) {   # slmgr.vbs, winrm.vbs, prnmngr.vbs ...
    if (Test-Path -LiteralPath $d) { Get-ChildItem -Path "$d\*" -Include *.vbs, *.wsf -File | ForEach-Object { Try-Add $_ 'wsh' } }
}
ConvertTo-Json -InputObject @($res) -Depth 3
"""

# Files signed here by Windows itself, so the script signature formats are checked against what Windows writes, not
# against this project's own idea of them. A throwaway self-signed code-signing certificate is created in
# CurrentUser\My and removed afterwards; it is not trusted, so the status is not Valid, but the signer is known.
WINDOWS_SELF_SIGNED = r"""
$ErrorActionPreference = 'Stop'
$res = New-Object System.Collections.ArrayList
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=4thehardway script signing test' -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
try {
    $files = [ordered]@{
        'test.vbs'   = 'WScript.Echo "4thehardway"'
        'test.vbe'   = 'WScript.Echo "4thehardway"'   # not encoded, but the file type picks the same signer as .vbs
        'test.js'    = 'WScript.Echo("4thehardway");'
        'test.wsf'   = "<job id=""t"">`r`n<script language=""VBScript"">`r`nWScript.Echo ""4thehardway""`r`n</script>`r`n</job>"
        'test.ps1'   = 'Write-Output 4thehardway'
        'test.cdxml' = '<?xml version="1.0" encoding="utf-8"?><PowerShellMetadata xmlns="http://schemas.microsoft.com/cmdlets-over-objects/2009/11"><Class ClassName="root/cimv2/Win32_Process"><Version>1.0</Version><DefaultNoun>T</DefaultNoun><InstanceCmdlets><GetCmdletParameters /></InstanceCmdlets></Class></PowerShellMetadata>'
        'test.mof'   = 'instance of MSFT_Credential { };'
    }
    foreach ($name in $files.Keys) {
        $p = Join-Path $env:SIGNED_FILES_WORK $name
        $tp = $null; $status = 'not signed'
        try {
            Set-Content -LiteralPath $p -Value $files[$name] -Encoding Ascii
            try { $null = Set-AuthenticodeSignature -FilePath $p -Certificate $cert -ErrorAction Stop } catch { $status = 'Set-AuthenticodeSignature: ' + $_.Exception.Message }
            $s = Get-AuthenticodeSignature -LiteralPath $p
            if ($null -eq $s.SignerCertificate -and $name -match '\.(vbs|vbe|js|wsf)$') {   # fall back to Windows Script Host's own signer
                try { (New-Object -ComObject Scripting.Signer).SignFile($p, '4thehardway script signing test') } catch { $status += '; Scripting.Signer: ' + $_.Exception.Message }
                $s = Get-AuthenticodeSignature -LiteralPath $p
            }
            if ($s.SignerCertificate) { $tp = $s.SignerCertificate.Thumbprint.ToLower(); $status = [string]$s.Status }
        } catch { $status = 'error: ' + $_.Exception.Message }
        [void]$res.Add([ordered]@{ path = $p; kind = 'self-' + $name.Split('.')[-1]; thumbprint = $tp; status = $status })
    }
} finally {
    Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue   # and its private key
}
ConvertTo-Json -InputObject @($res) -Depth 3
"""


def run(cmd, **kw):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def list_certs(scanner, paths):
    """Run the scanner's list mode; return list of certificate records."""
    out = []
    if scanner == "python":
        rc, so, se = run([sys.executable, os.path.join(ROOT, "emudhra_scan.py"), "--list-certs"] + paths)
        if rc != 0:
            raise RuntimeError("list mode failed: %s" % se)
        out = json.loads(so)
    else:
        for p in paths:                     # one file per call: -File passes each argument as a single string
            rc, so, se = run([scanner, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                              os.path.join(ROOT, "Scan-EmudhraRevoked.ps1"), "-ListCerts", "-Path", p])
            if rc != 0:
                raise RuntimeError("list mode failed on %s: %s %s" % (p, so[-500:], se[-500:]))
            d = json.loads(so.lstrip("\ufeff"))
            out += [d] if isinstance(d, dict) else d
    return out


def file_sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError as e:
        return "unreadable (%s)" % e


def windows_inventory(work):
    env = dict(os.environ, SIGNED_FILES_WORK=work)
    rc, so, se = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_INVENTORY], env=env)
    if rc != 0:
        raise RuntimeError("inventory failed: %s" % se)
    d = json.loads(so.lstrip("\ufeff") or "[]")
    return [d] if isinstance(d, dict) else d


def windows_self_signed(work):
    """Sign small script files with Windows' own tools; returns items for the files that got a signature."""
    env = dict(os.environ, SIGNED_FILES_WORK=work)
    rc, so, se = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SELF_SIGNED], env=env)
    if rc != 0:
        raise RuntimeError("signing test files failed: %s %s" % (so[-500:], se[-500:]))
    d = json.loads(so.lstrip("\ufeff") or "[]")
    d = [d] if isinstance(d, dict) else d
    for it in d:
        if not it["thumbprint"]:
            print("  note: Windows did not sign %s (status %s), so it was not tested" % (os.path.basename(it["path"]), it["status"]))
    return [it for it in d if it["thumbprint"]]


def macos_inventory(work):
    cands = ["/bin/ls", "/bin/cat", "/usr/bin/true", "/usr/bin/uname", "/usr/bin/codesign", "/usr/sbin/ping",
             "/System/Applications/Calculator.app/Contents/MacOS/Calculator"]
    items = []
    for i, p in enumerate(cands):
        if not os.path.exists(p):
            continue
        prefix = os.path.join(work, "c%d_" % i)
        run(["codesign", "-d", "--extract-certificates=" + prefix, p])
        signer = prefix + "0"
        if os.path.exists(signer):
            with open(signer, "rb") as fh:
                items.append({"path": p, "kind": "mach-o", "thumbprint": hashlib.sha1(fh.read()).hexdigest()})
    return items


def linux_inventory(work):
    keytool, jarsigner, jar = shutil.which("keytool"), shutil.which("jarsigner"), shutil.which("jar")
    if not (keytool and jarsigner and jar):
        raise RuntimeError("needs keytool, jarsigner and jar (a JDK)")
    src = os.path.join(work, "src")
    os.makedirs(src)
    with open(os.path.join(src, "hello.txt"), "w") as fh:
        fh.write("signed by the 4thehardway test suite\n")
    jarpath = os.path.join(work, "signed-test.jar")
    ks = os.path.join(work, "ks.p12")
    for cmd in ([jar, "cf", jarpath, "-C", src, "."],
                [keytool, "-genkeypair", "-keystore", ks, "-storetype", "PKCS12", "-storepass", "e2epass", "-keypass",
                 "e2epass", "-alias", "e2e", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                 "-dname", "CN=4thehardway signed-file test"],
                [jarsigner, "-keystore", ks, "-storepass", "e2epass", jarpath, "e2e"]):
        rc, so, se = run(cmd)
        if rc != 0:
            raise RuntimeError("%s failed: %s %s" % (cmd[0], so, se))
    der = subprocess.run([keytool, "-exportcert", "-keystore", ks, "-storepass", "e2epass", "-alias", "e2e"],
                         stdout=subprocess.PIPE).stdout
    return [{"path": jarpath, "kind": "jar", "thumbprint": hashlib.sha1(der).hexdigest()}]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True, choices=["python", "powershell", "pwsh"])
    ap.add_argument("--require-msi", action="store_true")
    a = ap.parse_args()
    system = platform.system()
    work = tempfile.mkdtemp(prefix="signed-files-")
    try:
        self_signed = []
        if system == "Windows":
            items = windows_inventory(work)
            if os.environ.get("E2E_ALLOW_STORE_CHANGES") == "1":   # adds and removes a certificate in CurrentUser\My
                self_signed = windows_self_signed(work)
                items += self_signed
            else:
                print("  note: set E2E_ALLOW_STORE_CHANGES=1 to also test script files signed here by Windows")
        elif system == "Darwin":
            items = macos_inventory(work)
        else:
            items = linux_inventory(work)
        kinds = sorted(set(i["kind"] for i in items))
        print("signed files identified by the OS tools: %d (%s)" % (len(items), ", ".join(kinds)))
        failures = []
        if not items:
            failures.append("no signed files found to test")
        if system == "Windows":
            for k in ("pe", "script") + (("msi",) if a.require_msi else ()):
                if k not in kinds:
                    failures.append("no signed %s file found to test" % k)
            for k in ("cdxml", "mof", "wsh"):          # tested when the runner has embedded-signed ones
                if k not in kinds:
                    print("  note: no embedded-signed %s file on this runner, so none was tested" % k)
            if os.environ.get("E2E_ALLOW_STORE_CHANGES") == "1":
                for k in ("self-ps1", "self-vbs"):     # Windows can always sign these two; the others are best effort
                    if k not in kinds:
                        failures.append("Windows did not sign the %s test file" % k[5:])
        before = dict((i["path"], file_sha256(i["path"])) for i in items)
        certs = list_certs(a.scanner, [i["path"] for i in items]) if items else []
        norm = lambda p: os.path.normcase(os.path.realpath(p))
        for it in items:
            mine = [c for c in certs if norm(c["location"]) == norm(it["path"]) and c["sha1"] == it["thumbprint"]]
            how = sorted(set("%s%s" % (c.get("found_as"), (" in " + c["container"]) if c.get("container") else "") for c in mine))
            ok = bool(mine)
            if it["kind"] == "msi":           # must come from the reassembled OLE signature stream
                ok = any((c.get("container") or "").startswith("OLE stream: DigitalSignature") for c in mine)
            if it["kind"] in ("script", "cdxml", "mof", "self-ps1", "self-cdxml", "self-mof"):
                ok = any(c.get("found_as") == "powershell-signature" for c in mine)
            if it["kind"] in ("wsh", "self-vbs", "self-vbe", "self-js", "self-wsf"):   # Windows Script Host
                ok = any(c.get("found_as") == "script-signature" for c in mine)
            shown = it.get("original") or it["path"]
            print("  %-4s %-10s %s  signer %s  via %s" % ("ok" if ok else "FAIL", it["kind"], shown, it["thumbprint"], how or "-"))
            if not ok:
                after = file_sha256(it["path"])
                if after != before[it["path"]]:
                    failures.append("%s changed during the test (sha256 %s -> %s); the OS signer no longer applies"
                                    % (it["path"], before[it["path"]], after))
                    continue
                found = ["%s (%s, %s)" % (c["sha1"], c.get("subject_cn"), c.get("found_as"))
                         for c in certs if norm(c["location"]) == norm(it["path"])]
                failures.append("signer certificate not extracted from %s (tested copy %s, %d bytes); scanner reported: %s"
                                % (shown, it["path"], os.path.getsize(it["path"]), ", ".join(found) or "no certificates"))
                if it["kind"].startswith("self-"):     # our own throwaway test file: show how Windows signed it
                    with open(it["path"], "rb") as fh:
                        raw = fh.read()
                    print("         file as signed by Windows (first 700 and last 200 bytes): %r ... %r" % (raw[:700], raw[-200:]))
        for f in failures:
            print("FAIL: " + f)
        if not failures:
            print("PASS: the scanner extracted the signer certificate from every real signed file")
        return 1 if failures else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
