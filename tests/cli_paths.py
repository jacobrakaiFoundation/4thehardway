#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Command-line path handling, for either scanner.

- A path that does not exist is an error (exit status 3), in scan mode and in list mode, so that a typo
  cannot look like a clean result.
- A relative path is resolved against the current directory. For PowerShell that is the current location
  (Set-Location), which is not the process working directory that .NET file APIs use.

usage: cli_paths.py --scanner python|powershell|pwsh SAMPLES_DIR   (SAMPLES_DIR from make_samples.py)
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = os.path.join(ROOT, "emudhra_scan.py")
PS = os.path.join(ROOT, "Scan-EmudhraRevoked.ps1")
SAMPLE = "fragmented.msi"


def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def ps_command(shell, location, args):
    """Run the script from PowerShell after Set-Location; the process itself starts in another directory."""
    q = lambda s: "'" + s.replace("'", "''") + "'"
    body = "Set-Location -LiteralPath %s; & %s %s; exit $LASTEXITCODE" % (q(location), q(PS), " ".join(args))
    return [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", body]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True, choices=["python", "powershell", "pwsh"])
    ap.add_argument("samples")
    a = ap.parse_args()
    samples = os.path.abspath(a.samples)
    failures = []

    def check(label, ok, detail=""):
        print("  %-4s %s%s" % ("ok" if ok else "FAIL", label, ("  (" + detail + ")") if detail and not ok else ""))
        if not ok:
            failures.append(label)

    with tempfile.TemporaryDirectory() as elsewhere:
        missing = os.path.join(samples, "does-not-exist.msi")
        if a.scanner == "python":
            scan = lambda args, cwd: run([sys.executable, PY] + args, cwd)
            rc, so, se = scan(["--no-trust-stores", "--no-processes", "--quiet", "--path", missing], elsewhere)
            check("missing path: exit 3 in scan mode", rc == 3 and "not found" in se, "rc=%d %s" % (rc, se.strip()))
            rc, so, se = scan(["--list-certs", missing], elsewhere)
            check("missing path: exit 3 in list mode", rc == 3 and "not found" in se, "rc=%d %s" % (rc, se.strip()))
            rc, so, se = scan(["--list-certs", SAMPLE], samples)
            certs = json.loads(so) if rc == 0 else []
            rc2, so2, se2 = scan(["--no-trust-stores", "--no-processes", "--quiet", "--path", SAMPLE], samples)
        else:
            rc, so, se = run(ps_command(a.scanner, samples, ["-NoTrustStores", "-NoProcesses", "-Quiet", "-Path", "'does-not-exist.msi'"]), elsewhere)
            check("missing path: exit 3 in scan mode", rc == 3 and "not found" in se, "rc=%d %s %s" % (rc, so.strip()[-300:], se.strip()[-300:]))
            rc, so, se = run(ps_command(a.scanner, samples, ["-ListCerts", "-Path", "'does-not-exist.msi'"]), elsewhere)
            check("missing path: exit 3 in list mode", rc == 3 and "not found" in se, "rc=%d %s %s" % (rc, so.strip()[-300:], se.strip()[-300:]))
            rc, so, se = run(ps_command(a.scanner, samples, ["-ListCerts", "-Path", "'%s'" % SAMPLE]), elsewhere)
            certs = json.loads(so.lstrip("﻿")) if rc == 0 and so.strip() else []
            certs = [certs] if isinstance(certs, dict) else certs
            rc2, so2, se2 = run(ps_command(a.scanner, samples, ["-NoTrustStores", "-NoProcesses", "-Quiet", "-Path", "'%s'" % SAMPLE]), elsewhere)
        want = os.path.normcase(os.path.join(samples, SAMPLE))
        located = [c for c in certs if os.path.normcase(os.path.abspath(os.path.join(samples, c["location"]))) == want]
        check("relative path in list mode is read from the current location", rc == 0 and len(located) >= 2,
              "rc=%d, %d certificates, locations %s" % (rc, len(certs), sorted(set(c["location"] for c in certs))[:3]))
        check("relative path in scan mode finds the critical findings (exit 2)", rc2 == 2, "rc=%d %s" % (rc2, (so2 + se2).strip()[-300:]))
    if failures:
        print("FAIL: %d check(s) failed" % len(failures))
        return 1
    print("PASS: command-line paths are handled correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
