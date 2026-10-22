# SPDX-License-Identifier: MIT
"""Unit tests for emudhra_scan.py. Standard library only: python -m unittest discover -s tests -v"""
import base64
import glob
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "emudhra_scan.py")
FIX = os.path.join(HERE, "fixtures")
IND_CERTS = os.path.join(ROOT, "indicators", "certs")

spec = importlib.util.spec_from_file_location("emudhra_scan", SCRIPT)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)
IND = scan.load_indicators()


def rb(path):
    with open(path, "rb") as fh:
        return fh.read()


def pem_to_der(path):
    data = rb(path)
    m = scan.PEM_RE.search(data)
    return scan._b64(m.group(2))


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def pkcs7(certs):
    """Degenerate PKCS#7 SignedData carrying certificates, like an Authenticode or JAR signature."""
    signed = tlv(0x06, bytes.fromhex("2a864886f70d010702"))
    data = tlv(0x06, bytes.fromhex("2a864886f70d010701"))
    sd = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b"") + tlv(0x30, data) + tlv(0xA0, b"".join(certs)) + tlv(0x31, b""))
    return tlv(0x30, signed + tlv(0xA0, sd))


def indicator_pem(prefix):
    return sorted(glob.glob(os.path.join(IND_CERTS, prefix + "*.pem")))[0]


CA_DER = pem_to_der(indicator_pem("EM_OV_CS_CA_G3C__emsign__"))
LEAF_DER = pem_to_der(os.path.join(FIX, "leaf_dv_g3b_we-have-a-problem.pem"))
BENIGN_DER = pem_to_der(os.path.join(FIX, "benign_ISRG_Root_X1.pem"))


def kinds(findings):
    return sorted(set((f["kind"], f["indicator"]) for f in findings))


class ScanBase(unittest.TestCase):
    def scanner(self):
        return scan.Scanner(IND, 768 * 1024 * 1024, quiet=True)

    def scan_blob(self, data, name="blob.bin"):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, name)
            with open(p, "wb") as fh:
                fh.write(data)
            sc = self.scanner()
            sc.scan_file(p, "file", force=True)
            return sc.findings


class TestIndicators(ScanBase):
    def test_self_test(self):
        ok, res = scan.self_test(IND)
        self.assertTrue(ok, res)

    def test_embedded_indicators_match_json(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "embed_indicators.py"), "--check"])
        self.assertEqual(r.returncode, 0, "run tools/embed_indicators.py after editing indicators.json")

    def test_every_indicator_certificate_is_detected(self):
        names = {e["name"] for e in IND.data["compromised_cas"]}
        roots = {e["name"] for e in IND.data["affected_roots"]}
        seen = set()
        for p in glob.glob(os.path.join(IND_CERTS, "*.pem")):
            c = scan.parse_cert(pem_to_der(p))
            self.assertIsNotNone(c, p)
            kind, e = IND.classify(c)
            if e["name"] in names:
                self.assertEqual(kind, "COMPROMISED_CA_CERT", p)
            else:
                self.assertIn(e["name"], roots)
                self.assertEqual(kind, "AFFECTED_ROOT", p)
            seen.add(e["name"])
        self.assertEqual(seen, names | roots)

    def test_malleated_copy_is_detected(self):
        c = scan.parse_cert(pem_to_der(indicator_pem("EM_EV_TLS_CA_G3B__malleated__")))
        self.assertEqual(IND.classify(c)[0], "COMPROMISED_CA_CERT")

    def test_minted_leaves_are_detected(self):
        for name in ("leaf_dv_g3b_we-have-a-problem.pem", "leaf_dv_g3b_filippo_no_cn.pem"):
            c = scan.parse_cert(pem_to_der(os.path.join(FIX, name)))
            kind, e = IND.classify(c)
            self.assertEqual((kind, e["name"]), ("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"), name)

    def test_near_miss_and_benign_are_clean(self):
        for name in ("nearmiss_EM_DV_TLS_CA_G3A-1.pem", "benign_ISRG_Root_X1.pem"):
            c = scan.parse_cert(pem_to_der(os.path.join(FIX, name)))
            self.assertIsNotNone(c)
            self.assertIsNone(IND.classify(c), name)

    def test_parser_fields(self):
        c = scan.parse_cert(CA_DER)
        e = [x for x in IND.data["compromised_cas"] if x["name"] == "EM OV CS CA - G3C"][0]
        self.assertEqual(c.subject_cn, "EM OV CS CA - G3C")
        self.assertEqual(c.ski, e["subject_key_id"])
        self.assertEqual(c.spki_sha256, e["spki_sha256"])
        self.assertTrue(c.not_before.startswith("2025-04-30"))

    def test_garbage_is_not_a_certificate(self):
        for junk in (b"", b"\x30\x82\x00\x10" + b"\x00" * 16, os.urandom(300), b"\x30\x80\x00\x00"):
            self.assertIsNone(scan.parse_cert(junk))


class TestContainers(ScanBase):
    def test_fake_signed_exe(self):
        blob = b"MZ" + os.urandom(5000) + pkcs7([LEAF_DER, CA_DER]) + os.urandom(3000)
        k = kinds(self.scan_blob(blob, "setup.exe"))
        self.assertIn(("COMPROMISED_CA_CERT", "EM OV CS CA - G3C"), k)
        self.assertIn(("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"), k)

    def test_large_file_uses_mmap(self):
        blob = b"\x7fELF" + os.urandom(3 * 1024 * 1024) + LEAF_DER + os.urandom(1024)
        self.assertIn(("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"), kinds(self.scan_blob(blob, "libfoo.so.1")))

    def test_powershell_signature_block(self):
        b64 = base64.b64encode(pkcs7([CA_DER])).decode()
        lines = "\r\n".join("# " + b64[i:i + 64] for i in range(0, len(b64), 64))
        script = "Write-Host hi\r\n\r\n# SIG # Begin signature block\r\n" + lines + "\r\n# SIG # End signature block\r\n"
        f = self.scan_blob(script.encode(), "script.ps1")
        self.assertEqual(kinds(f), [("COMPROMISED_CA_CERT", "EM OV CS CA - G3C")])
        self.assertEqual(f[0]["found_as"], "powershell-signature")

    def test_jar_signature_member(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            z.writestr("META-INF/CERT.RSA", pkcs7([LEAF_DER]))
        f = self.scan_blob(bio.getvalue(), "app.jar")
        self.assertEqual(kinds(f), [("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B")])
        self.assertEqual(f[0]["container"], "META-INF/CERT.RSA")

    def test_nested_bundle(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("AppxSignature.p7x", b"PKCX" + pkcs7([CA_DER]))
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("App_x64.appx", inner.getvalue())
        f = self.scan_blob(outer.getvalue(), "App.appxbundle")
        self.assertEqual(kinds(f), [("COMPROMISED_CA_CERT", "EM OV CS CA - G3C")])
        self.assertEqual(f[0]["container"], "App_x64.appx!/AppxSignature.p7x")

    def test_trusted_certificate_pem(self):
        aux = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("2b06010505070301"))))
        body = base64.encodebytes(LEAF_DER + aux)
        pem = b"-----BEGIN TRUSTED CERTIFICATE-----\n" + body + b"-----END TRUSTED CERTIFICATE-----\n"
        self.assertEqual(kinds(self.scan_blob(pem, "x.pem")), [("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B")])

    def test_pkcs7_pem(self):
        body = base64.encodebytes(pkcs7([CA_DER, BENIGN_DER]))
        pem = b"-----BEGIN PKCS7-----\n" + body + b"-----END PKCS7-----\n"
        self.assertEqual(kinds(self.scan_blob(pem, "chain.p7b")), [("COMPROMISED_CA_CERT", "EM OV CS CA - G3C")])

    def test_escaped_pem_in_json(self):
        pem = rb(os.path.join(FIX, "leaf_dv_g3b_we-have-a-problem.pem")).decode().strip()
        js = json.dumps({"cert": pem}).encode()
        self.assertIn(b"\\n", js)
        self.assertEqual(kinds(self.scan_blob(js, "config.json")), [("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B")])

    def test_benign_bundle_is_clean(self):
        pem = rb(os.path.join(FIX, "benign_ISRG_Root_X1.pem")) + rb(os.path.join(FIX, "nearmiss_EM_DV_TLS_CA_G3A-1.pem"))
        self.assertEqual(self.scan_blob(pem, "bundle.pem"), [])

    def test_windows_disallowed_store_is_info(self):
        sc = self.scanner()
        sc.add(scan.parse_cert(CA_DER), "Windows certificate store: Disallowed", "trust-store", store="Disallowed")
        sc.add(scan.parse_cert(CA_DER), "Windows certificate store: CA", "trust-store", store="CA")
        sev = sorted(f["severity"] for f in sc.findings)
        self.assertEqual(sev, ["CRITICAL", "INFO"])


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        r = subprocess.run([sys.executable, SCRIPT, "--no-trust-stores", "--no-processes", "--quiet"] + list(args),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode("utf-8", "replace")

    def test_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "readme.txt"), "w") as fh:
                fh.write("nothing here")
            rc, out = self.run_cli("--path", d)
            self.assertEqual(rc, 0, out)
            root = indicator_pem("emSign_ECC_Root_CA_G3__root__")
            with open(os.path.join(d, "roots.pem"), "wb") as fh:
                fh.write(rb(root))
            rc, out = self.run_cli("--path", d)
            self.assertEqual(rc, 1, out)
            with open(os.path.join(d, "server.crt"), "wb") as fh:
                fh.write(rb(os.path.join(FIX, "leaf_dv_g3b_we-have-a-problem.pem")))
            jpath = os.path.join(d, "report.json")
            rc, out = self.run_cli("--path", d, "--json", jpath)
            self.assertEqual(rc, 2, out)
            with open(jpath) as fh:
                doc = json.load(fh)
            self.assertEqual(sorted(f["kind"] for f in doc["findings"]), ["AFFECTED_ROOT", "ISSUED_BY_COMPROMISED_CA"])

    def test_tool_skips_its_own_files(self):
        rc, out = self.run_cli("--path", ROOT)
        self.assertEqual(rc, 0, out)
        rc, out = self.run_cli("--path", ROOT, "--include-self")
        self.assertEqual(rc, 2, out)


if __name__ == "__main__":
    unittest.main()
