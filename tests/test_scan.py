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
import hashlib
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cfb_writer  # noqa: E402
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


def _b64_lines(blob):
    b64 = base64.b64encode(blob).decode()
    return [b64[i:i + 64] for i in range(0, len(b64), 64)]


def ps1_signed(blob, utf16=False):
    """A PowerShell script with an Authenticode signature block, as Set-AuthenticodeSignature writes it."""
    text = "Write-Host hi\r\n\r\n# SIG # Begin signature block\r\n" + \
        "\r\n".join("# " + l for l in _b64_lines(blob)) + "\r\n# SIG # End signature block\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le") if utf16 else text.encode()


def ps1xml_signed(blob):
    """A .ps1xml file: the same signature block inside XML comments."""
    return ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<Configuration></Configuration>\r\n"
            "<!-- SIG # Begin signature block -->\r\n" + "\r\n".join("<!-- " + l + " -->" for l in _b64_lines(blob)) +
            "\r\n<!-- SIG # End signature block -->\r\n").encode()


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
        """Consistency only: the indicators were built from these same certificates. Their correctness is
        checked independently against Mozilla's published notice in TestMozillaNotice."""
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

    def test_ps1xml_xml_comment_signature_block(self):
        # .ps1xml/.cdxml files carry the signature in XML comments (found missing on a real Windows runner)
        f = self.scan_blob(ps1xml_signed(pkcs7([CA_DER])), "Format.ps1xml")
        self.assertEqual([(x["kind"], x["found_as"]) for x in f], [("COMPROMISED_CA_CERT", "powershell-signature")])

    def test_utf16_powershell_script(self):
        f = self.scan_blob(ps1_signed(pkcs7([CA_DER]), utf16=True), "Module.psd1")
        self.assertEqual([(x["kind"], x["found_as"]) for x in f], [("COMPROMISED_CA_CERT", "powershell-signature")])

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


def msi_streams():
    """Streams of an MSI-like compound file: a large signature (regular sectors) and a small one (mini stream)."""
    return [("\x05DigitalSignature", pkcs7([BENIGN_DER, BENIGN_DER, CA_DER, BENIGN_DER])),
            ("Data", bytes(range(256)) * 80),
            ("\x05MsiDigitalSignatureEx", pkcs7([LEAF_DER])),
            ("\x05SummaryInformation", bytes(range(200)) * 7)]


class TestOle(ScanBase):
    def test_streams_are_large_and_small(self):
        s = dict(msi_streams())
        self.assertGreaterEqual(len(s["\x05DigitalSignature"]), 4096)      # regular FAT sectors
        self.assertLess(len(s["\x05MsiDigitalSignatureEx"]), 4096)         # mini stream

    def test_fragmented_v3_needs_reassembly(self):
        blob = cfb_writer.build(msi_streams(), version=3)
        raw = [c.subject_cn for c, _ in scan.extract_certs(blob, IND)]
        self.assertEqual(raw, [], "raw carving should NOT find certificates split across fragmented sectors")
        got = dict(scan.cfb_signature_streams(blob))
        want = dict(msi_streams())
        self.assertEqual(got["DigitalSignature"], want["\x05DigitalSignature"])
        self.assertEqual(got["MsiDigitalSignatureEx"], want["\x05MsiDigitalSignatureEx"])
        f = self.scan_blob(blob, "setup.msi")
        self.assertEqual(sorted((x["kind"], x["indicator"], x["container"]) for x in f), [
            ("COMPROMISED_CA_CERT", "EM OV CS CA - G3C", "OLE stream: DigitalSignature"),
            ("ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B", "OLE stream: MsiDigitalSignatureEx")])

    def test_v4_found_once(self):
        blob = cfb_writer.build(msi_streams(), version=4)
        self.assertTrue(any(c.subject_cn == "EM OV CS CA - G3C" for c, _ in scan.extract_certs(blob, IND)),
                        "4096-byte sectors hold the whole certificate, so raw carving also finds it")
        f = [x for x in self.scan_blob(blob, "setup.msi") if x["indicator"] == "EM OV CS CA - G3C"]
        self.assertEqual(len(f), 1, "OLE stream and raw scan of the same file must give one finding")
        self.assertEqual(f[0]["container"], "OLE stream: DigitalSignature")

    def test_msi_inside_zip(self):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("payload/setup.msi", cfb_writer.build(msi_streams(), version=3))
        f = self.scan_blob(bio.getvalue(), "bundle.zip")
        self.assertIn(("COMPROMISED_CA_CERT", "payload/setup.msi!/OLE stream: DigitalSignature"),
                      [(x["kind"], x["container"]) for x in f])

    def test_olefile_agrees_with_writer_and_reader(self):
        try:
            import olefile
        except ImportError:
            self.skipTest("olefile not installed (CI installs it)")
        for ver in (3, 4):
            blob = cfb_writer.build(msi_streams(), version=ver)
            ole = olefile.OleFileIO(io.BytesIO(blob))
            for name, data in msi_streams():
                self.assertEqual(ole.openstream(name).read(), data, (ver, name))
            mine = dict(scan.cfb_signature_streams(blob))
            self.assertEqual(mine["DigitalSignature"], ole.openstream("\x05DigitalSignature").read())

    def test_corrupt_files_do_not_crash(self):
        good = cfb_writer.build(msi_streams(), version=3)
        cases = [good[:n] for n in (0, 8, 511, 512, 1024, 1500, 4000, len(good) - 1)]
        for i in range(300):
            h = hashlib.sha256(b"mutation %d" % i).digest()
            b = bytearray(good)
            for k in range(0, 8, 2):                     # flip 4 bytes in the first 4 KB (header, FAT, directory)
                pos = int.from_bytes(h[k:k + 2], "big") % 4096
                b[pos] = h[k + 8]
            cases.append(bytes(b))
        for blob in cases:
            list(scan.cfb_signature_streams(blob))       # must not raise
            self.scan_blob(blob, "fuzz.msi")


class TestListCertsAndTimeLimit(ScanBase):
    def run_cli(self, *args):
        r = subprocess.run([sys.executable, SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode("utf-8", "replace")

    def test_list_certs_reports_unrelated_certificates(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "setup.msi")
            with open(p, "wb") as fh:
                fh.write(cfb_writer.build(msi_streams(), version=3))
            rc, out = self.run_cli("--list-certs", p, FIX)
            self.assertEqual(rc, 0, out)
            certs = json.loads(out)
            sha1s = {(os.path.basename(c["location"]), c["sha1"]) for c in certs}
            self.assertIn(("setup.msi", hashlib.sha1(BENIGN_DER).hexdigest()), sha1s)   # benign cert, OLE stream
            self.assertIn(("benign_ISRG_Root_X1.pem", hashlib.sha1(BENIGN_DER).hexdigest()), sha1s)
            self.assertIn(("setup.msi", hashlib.sha1(CA_DER).hexdigest()), sha1s)

    def test_deadline_stops_the_walk(self):
        sc = scan.Scanner(IND, 768 * 1024 * 1024, quiet=True, deadline=time.time() - 1)
        sc.walk([FIX], "file")
        self.assertEqual(sc.stats["files_scanned"], 0)
        self.assertTrue(sc.stats["time_limited"])

    def test_generous_time_limit_completes(self):
        with tempfile.TemporaryDirectory() as d:     # outside tests/, which the scanner skips as its own files
            src = os.path.join(d, "src")
            os.mkdir(src)
            for p in glob.glob(os.path.join(FIX, "*.pem")):
                with open(os.path.join(src, os.path.basename(p)), "wb") as fh:
                    fh.write(rb(p))
            j = os.path.join(d, "r.json")
            rc, out = self.run_cli("--no-trust-stores", "--no-processes", "--quiet", "--time-limit", "600",
                                   "--path", src, "--json", j)
            with open(j) as fh:
                doc = json.load(fh)
            self.assertFalse(doc["stats"]["time_limited"])
            self.assertGreater(doc["stats"]["files_scanned"], 0)


class TestMozillaNotice(unittest.TestCase):
    """Independent check: compare the indicators with Mozilla's notice to trust store operators
    (Bug 2083449, attachment 9664786), kept verbatim in tests/published/."""

    @classmethod
    def setUpClass(cls):
        text = rb(os.path.join(HERE, "published", "mozilla_notice_bug2083449_attachment9664786.txt")).decode("utf-8")
        cls.blocks = []
        cur = None
        for line in text.splitlines():
            line = line.strip()
            m = re.match(r"^(EM (?:DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC])\b.*CCADB (A\d+)$", line)
            if m:
                cur = {"name": m.group(1), "ccadb": m.group(2)}
                cls.blocks.append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^SHA-256 ([0-9A-Fa-f]{64})$", line)
            if m:
                cur["sha256"] = m.group(1).lower()
            m = re.match(r"^SHA256 SPKI ([0-9a-f]{60,64})$", line)
            if m:
                cur["spki_prefix"] = m.group(1)
            m = re.match(r"^serial ([0-9a-f]+)", line)
            if m:
                cur["serial"] = m.group(1)
        cls.roots = {m.group(1): m.group(2) for m in
                     re.finditer(r"(emSign Root TLS CA - G3|emSign ECC Root CA - G3) \(SPKI SHA-256: ([0-9a-f]{64})\)", text)}
        cls.ind = {e["name"]: e for e in IND.data["compromised_cas"]}

    def test_notice_parsed(self):
        self.assertEqual(len(self.blocks), 16, "8 emSign-issued + 8 Sectigo cross-certificates")
        self.assertEqual(len({b["name"] for b in self.blocks}), 8)
        self.assertEqual(len(self.roots), 2)

    def test_same_eight_cas(self):
        self.assertEqual({b["name"] for b in self.blocks}, set(self.ind))

    def test_every_published_certificate_is_an_indicator(self):
        for b in self.blocks:
            fps = {c["sha256"] for c in self.ind[b["name"]]["certificates"]}
            self.assertIn(b["sha256"], fps, b)
            serials = {c["serial"] for c in self.ind[b["name"]]["certificates"]}
            self.assertIn(b["serial"].lstrip("0"), serials, b)

    def test_published_key_hashes_match(self):
        n = 0
        for b in self.blocks:
            if "spki_prefix" in b:
                n += 1
                self.assertTrue(self.ind[b["name"]]["spki_sha256"].startswith(b["spki_prefix"]), b)
        self.assertEqual(n, 8)

    def test_root_key_hashes_match(self):
        roots = {e["name"]: e["spki_sha256"] for e in IND.data["affected_roots"]}
        for name, spki in self.roots.items():
            self.assertEqual(roots[name], spki, name)

    def test_shipped_certificate_files_hash_to_published_fingerprints(self):
        files = {hashlib.sha256(pem_to_der(p)).hexdigest() for p in glob.glob(os.path.join(IND_CERTS, "*.pem"))}
        for b in self.blocks:
            self.assertIn(b["sha256"], files, b["name"])


class TestCheckReport(unittest.TestCase):
    def run_check(self, doc, *args):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            if doc is not None:
                with open(p, "w") as fh:
                    fh.write(doc if isinstance(doc, str) else json.dumps(doc))
            r = subprocess.run([sys.executable, os.path.join(HERE, "check_report.py"), p] + list(args),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return r.returncode, r.stdout.decode()

    def report(self, certs=120, findings=()):
        return {"meta": {"version": "x"}, "stats": {"trust_store_sources": 3, "files_scanned": 0,
                                                     "certificates_parsed": certs}, "findings": list(findings)}

    def test_missing_or_broken_report_fails(self):
        self.assertEqual(self.run_check(None)[0], 1)
        self.assertEqual(self.run_check("{not json")[0], 1)

    def test_too_few_certificates_fails(self):
        self.assertEqual(self.run_check(self.report(certs=3), "--min-certs", "50")[0], 1)
        self.assertEqual(self.run_check(self.report(certs=120), "--min-certs", "50")[0], 0)

    def test_expectations(self):
        f = {"severity": "CRITICAL", "kind": "COMPROMISED_CA_CERT", "indicator": "EM DV TLS CA - G3B",
             "location": "Windows certificate store: CA", "certificate": {"sha256": "a" * 64}}
        ok = "CRITICAL:COMPROMISED_CA_CERT:EM DV TLS CA - G3B:store: CA"
        self.assertEqual(self.run_check(self.report(findings=[f]), "--expect", ok)[0], 0)
        self.assertEqual(self.run_check(self.report(findings=[]), "--expect", ok)[0], 1)
        one = dict(self.report(), findings=f)          # PowerShell's one-item serialization
        self.assertEqual(self.run_check(one, "--expect", ok)[0], 0)


if __name__ == "__main__":
    unittest.main()
