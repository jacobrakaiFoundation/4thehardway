#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end test: plant compromised CA certificates in REAL operating-system certificate stores, run a
scanner's quick mode, and require it to report them.

  Windows : CurrentUser "CA" store (expect CRITICAL) and CurrentUser "Disallowed" store (expect INFO)
  macOS   : a new keychain added to the user's keychain search list
  Linux   : an NSS database (cert9.db, via certutil) and a Java JKS cacerts (via keytool)
  all     : a PEM bundle named by SSL_CERT_FILE

This changes OS certificate stores, so it refuses to run unless E2E_ALLOW_STORE_CHANGES=1 (CI runners are
disposable). Everything it adds is removed afterwards.

usage: e2e_os_stores.py --scanner python|powershell|pwsh [--require-nss] [--require-java]
"""
import argparse
import glob
import os
import platform
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from test_scan import pem_to_der, indicator_pem, rb, FIX  # noqa: E402

A = indicator_pem("EM_DV_TLS_CA_G3B__emsign__")           # -> OS store
B = indicator_pem("EM_OV_CS_CA_G3C__emsign__")            # -> Windows Disallowed / Java cacerts
C = indicator_pem("EM_EV_TLS_CA_G3C__sectigo-cross__")    # -> SSL_CERT_FILE bundle
D = indicator_pem("EM_OV_TLS_CA_G3B__emsign__")           # -> NSS database


def run(cmd, **kw):
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


def must(cmd, **kw):
    r = run(cmd, **kw)
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode != 0:
        raise RuntimeError("command failed (%d): %s\n%s" % (r.returncode, " ".join(cmd), out))
    return out


def ps(script):
    return must(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True, choices=["python", "powershell", "pwsh"])
    ap.add_argument("--require-nss", action="store_true")
    ap.add_argument("--require-java", action="store_true")
    a = ap.parse_args()
    if os.environ.get("E2E_ALLOW_STORE_CHANGES") != "1":
        print("refusing to change OS certificate stores; set E2E_ALLOW_STORE_CHANGES=1 (CI only)")
        return 2

    system = platform.system()
    work = tempfile.mkdtemp(prefix="e2e-stores-")
    env = dict(os.environ)
    expects, cleanups = [], []
    store_label = "Windows certificate store: " + ("CA" if a.scanner == "python" else "CurrentUser\\CA")
    disallowed_label = "Windows certificate store: " + ("Disallowed" if a.scanner == "python" else "CurrentUser\\Disallowed")

    for name, p in (("a", A), ("b", B), ("c", C), ("d", D)):
        with open(os.path.join(work, name + ".cer"), "wb") as fh:
            fh.write(pem_to_der(p))
        with open(os.path.join(work, name + ".pem"), "wb") as fh:
            fh.write(rb(p))

    # Every OS: a PEM bundle named by SSL_CERT_FILE (benign root + compromised cross-certificate).
    bundle = os.path.join(work, "e2e-bundle.pem")
    with open(bundle, "wb") as fh:
        fh.write(rb(os.path.join(FIX, "benign_ISRG_Root_X1.pem")) + rb(C))
    env["SSL_CERT_FILE"] = bundle
    expects.append("CRITICAL:COMPROMISED_CA_CERT:EM EV TLS CA - G3C:e2e-bundle.pem")

    try:
        if system == "Windows":
            for store, name in (("CA", "a"), ("Disallowed", "b")):
                cer = os.path.join(work, name + ".cer")
                script = ("$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList '%s'; "
                          "$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('%s','CurrentUser'); "
                          "$s.Open('ReadWrite'); $s.%s($c); $s.Close()")
                ps(script % (cer, store, "Add"))
                cleanups.append(lambda cer=cer, store=store: ps(script % (cer, store, "Remove")))
            expects.append("CRITICAL:COMPROMISED_CA_CERT:EM DV TLS CA - G3B:" + store_label)
            expects.append("INFO:COMPROMISED_CA_CERT:EM OV CS CA - G3C:" + disallowed_label)

        elif system == "Darwin":
            kc = os.path.join(work, "e2e.keychain")
            before = must(["security", "list-keychains", "-d", "user"])
            old = [l.strip().strip('"') for l in before.splitlines() if l.strip()]
            must(["security", "create-keychain", "-p", "e2e", kc])
            cleanups.append(lambda: run(["security", "delete-keychain", kc]))
            must(["security", "list-keychains", "-d", "user", "-s", kc] + old)
            cleanups.append(lambda: run(["security", "list-keychains", "-d", "user", "-s"] + old))
            must(["security", "add-certificates", "-k", kc, os.path.join(work, "a.pem")])
            expects.append("CRITICAL:COMPROMISED_CA_CERT:EM DV TLS CA - G3B:e2e.keychain")

        elif system == "Linux":
            home = os.path.join(work, "home")                # the scanner reads ~/.pki/nssdb
            nssdb = os.path.join(home, ".pki", "nssdb")
            os.makedirs(nssdb)
            env["HOME"] = home
            if shutil.which("certutil"):
                must(["certutil", "-N", "-d", "sql:" + nssdb, "--empty-password"])
                must(["certutil", "-A", "-d", "sql:" + nssdb, "-n", "e2e", "-t", ",,", "-i", os.path.join(work, "d.pem")])
                expects.append("CRITICAL:COMPROMISED_CA_CERT:EM OV TLS CA - G3B:cert9.db")
            elif a.require_nss:
                raise RuntimeError("certutil not found (install libnss3-tools)")
            else:
                print("note: certutil not found; NSS database not tested")
            keytool = shutil.which("keytool")
            if keytool:
                jh = os.path.join(work, "java")
                os.makedirs(os.path.join(jh, "lib", "security"))
                must([keytool, "-importcert", "-noprompt", "-storetype", "JKS", "-alias", "e2e", "-storepass", "changeit",
                      "-keystore", os.path.join(jh, "lib", "security", "cacerts"), "-file", os.path.join(work, "b.cer")])
                env["JAVA_HOME"] = jh
                expects.append("CRITICAL:COMPROMISED_CA_CERT:EM OV CS CA - G3C:cacerts")
            elif a.require_java:
                raise RuntimeError("keytool not found")
            else:
                print("note: keytool not found; Java cacerts not tested")

        report = os.path.join(work, "e2e-report.json")
        if a.scanner == "python":
            cmd = [sys.executable, os.path.join(ROOT, "emudhra_scan.py"), "--quick", "--no-processes", "--quiet",
                   "--json", report]
        else:
            cmd = [a.scanner, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                   os.path.join(ROOT, "Scan-EmudhraRevoked.ps1"), "-Quick", "-NoProcesses", "-Quiet", "-JsonOut", report]
        r = run(cmd, env=env)
        print(r.stdout.decode("utf-8", "replace"))
        print("scanner exit code:", r.returncode)
        if r.returncode not in (0, 1, 2):
            print("FAIL: scanner exit code %d" % r.returncode)
            return 1
        chk = [sys.executable, os.path.join(HERE, "check_report.py"), report, "--min-certs", "50", "--min-sources", "1"]
        for e in expects:
            chk += ["--expect", e]
        r = run(chk)
        print(r.stdout.decode("utf-8", "replace"))
        if r.returncode == 0:
            print("PASS: %d planted certificates found in real OS stores" % len(expects))
        return r.returncode
    finally:
        for c in reversed(cleanups):
            try:
                c()
            except Exception as e:
                print("cleanup warning:", e)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
