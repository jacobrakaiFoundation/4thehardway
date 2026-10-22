#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real-world check: the scanner must extract the signer certificate from files that are really signed,
as identified by the operating system's own signature tools (not by this project's code).

  Windows : signed .msi (C:\\Windows\\Installer), .exe/.dll, and PowerShell scripts with EMBEDDED Authenticode
            signatures; signer thumbprint from Get-AuthenticodeSignature
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
$want = @{ msi = 4; pe = 6; script = 4 }
$got = @{ msi = 0; pe = 0; script = 0 }
$res = New-Object System.Collections.ArrayList
function Try-Add($f, $kind) {
    if ($got[$kind] -ge $want[$kind]) { return }
    if ($f.Length -gt 256MB) { return }   # Scan-EmudhraRevoked.ps1 skips files over -MaxSizeMB (default 256)
    $s = Get-AuthenticodeSignature -LiteralPath $f.FullName
    if ($null -eq $s -or $s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate) { return }
    if ($s.PSObject.Properties['SignatureType'] -and [string]$s.SignatureType -ne 'Authenticode') { return }  # embedded only, not catalog
    [void]$res.Add([ordered]@{ path = $f.FullName; kind = $kind; thumbprint = $s.SignerCertificate.Thumbprint.ToLower(); subject = $s.SignerCertificate.Subject })
    $got[$kind]++
}
Get-ChildItem -LiteralPath "$env:SystemRoot\Installer" -Filter *.msi -File | Select-Object -First 200 | ForEach-Object { Try-Add $_ 'msi' }
foreach ($d in @("$env:ProgramFiles\PowerShell\7", "$env:ProgramFiles\Git\cmd", "$env:ProgramFiles\Git\mingw64\bin", "$env:SystemRoot\System32")) {
    if (Test-Path -LiteralPath $d) { Get-ChildItem -Path "$d\*" -Include *.exe, *.dll -File | Select-Object -First 150 | ForEach-Object { Try-Add $_ 'pe' } }
}
# Defender's modules are skipped: Defender platform updates rewrite them in place, so they can change or be
# locked between this inventory and the scan.
Get-ChildItem -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0" -Recurse -File -Include *.ps1, *.psm1, *.psd1, *.ps1xml |
    Where-Object { $_.FullName -notmatch '\\Modules\\(ConfigDefender|ConfigDefenderPerformance|Defender)\\' } |
    Select-Object -First 600 | ForEach-Object { Try-Add $_ 'script' }
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


def windows_inventory():
    rc, so, se = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_INVENTORY])
    if rc != 0:
        raise RuntimeError("inventory failed: %s" % se)
    d = json.loads(so.lstrip("\ufeff") or "[]")
    return [d] if isinstance(d, dict) else d


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
        if system == "Windows":
            items = windows_inventory()
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
        before = dict((i["path"], file_sha256(i["path"])) for i in items)
        certs = list_certs(a.scanner, [i["path"] for i in items]) if items else []
        norm = lambda p: os.path.normcase(os.path.realpath(p))
        for it in items:
            mine = [c for c in certs if norm(c["location"]) == norm(it["path"]) and c["sha1"] == it["thumbprint"]]
            how = sorted(set("%s%s" % (c.get("found_as"), (" in " + c["container"]) if c.get("container") else "") for c in mine))
            ok = bool(mine)
            if it["kind"] == "msi":           # must come from the reassembled OLE signature stream
                ok = any((c.get("container") or "").startswith("OLE stream: DigitalSignature") for c in mine)
            if it["kind"] == "script":
                ok = any(c.get("found_as") == "powershell-signature" for c in mine)
            print("  %-4s %-6s %s  signer %s  via %s" % ("ok" if ok else "FAIL", it["kind"], it["path"], it["thumbprint"], how or "-"))
            if not ok:
                after = file_sha256(it["path"])
                if after != before[it["path"]]:
                    failures.append("%s changed during the test (sha256 %s -> %s); the OS signer no longer applies"
                                    % (it["path"], before[it["path"]], after))
                    continue
                found = ["%s (%s, %s)" % (c["sha1"], c.get("subject_cn"), c.get("found_as"))
                         for c in certs if norm(c["location"]) == norm(it["path"])]
                failures.append("signer certificate not extracted from %s (%d bytes); scanner reported: %s"
                                % (it["path"], os.path.getsize(it["path"]), ", ".join(found) or "no certificates"))
        for f in failures:
            print("FAIL: " + f)
        if not failures:
            print("PASS: the scanner extracted the signer certificate from every real signed file")
        return 1 if failures else 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
