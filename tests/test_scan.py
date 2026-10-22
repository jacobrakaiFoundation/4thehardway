# SPDX-License-Identifier: MIT
"""Unit tests for emudhra_scan.py. Standard library only: python -m unittest discover -s tests -v"""
import base64
import glob
import importlib.util
import io
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import threading
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
    """DER of the first certificate in a PEM file, decoded here rather than by the scanner under test."""
    m = re.search(rb"-----BEGIN [A-Z0-9 ]*CERTIFICATE-----(.*?)-----END ", rb(path), re.S)
    return base64.b64decode(b"".join(m.group(1).split()))


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


def mof_signed(blob):
    """A DSC .mof file: the signature block inside /* */ comments ("/" is a base64 character)."""
    return ("instance of MSFT_Example\r\n{\r\n};\r\n\r\n/* SIG # Begin signature block */\r\n" +
            "\r\n".join("/* " + l + " */" for l in _b64_lines(blob)) + "\r\n/* SIG # End signature block */\r\n").encode()


def wsh_signed(blob, lang="vbs", utf16=False):
    """A Windows Script Host script signed by Scripting.Signer: comment lines "'' SIG ''" (VBScript) or "// SIG //"
    (JScript), 44 base64 characters per line. "SIG" and "/" are base64 characters, so the prefixes must be removed."""
    pre = "'' SIG '' " if lang == "vbs" else "// SIG // "
    code = 'WScript.Echo "hi"\r\n' if lang == "vbs" else 'WScript.Echo("hi");\r\n'
    b64 = base64.b64encode(blob).decode()
    text = code + "\r\n".join([pre + "Begin signature block"] + [pre + b64[i:i + 44] for i in range(0, len(b64), 44)] +
                               [pre + "End signature block"]) + "\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le") if utf16 else text.encode()


def wsf_signed(blob):
    """A .wsf file: the signature is a <signature> element of "** SIG **" lines."""
    b64 = base64.b64encode(blob).decode()
    return ('<?xml version="1.0" ?>\r\n<job>\r\n<script language="VBScript">\r\nWScript.Echo "hi"\r\n</script>\r\n'
            "<signature>\r\n" + "\r\n".join("** SIG ** " + b64[i:i + 44] for i in range(0, len(b64), 44)) +
            "\r\n</signature>\r\n</job>\r\n").encode()


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

    def test_mof_comment_signature_block(self):
        f = self.scan_blob(mof_signed(pkcs7([CA_DER])), "Resource.schema.mof")
        self.assertEqual([(x["kind"], x["found_as"]) for x in f], [("COMPROMISED_CA_CERT", "powershell-signature")])

    def test_windows_script_host_signature_blocks(self):
        for name, data in (("logon.vbs", wsh_signed(pkcs7([CA_DER]), "vbs")),
                           ("tool.js", wsh_signed(pkcs7([CA_DER]), "js")),
                           ("unicode.vbs", wsh_signed(pkcs7([CA_DER]), "vbs", utf16=True)),
                           ("setup.wsf", wsf_signed(pkcs7([CA_DER])))):
            f = self.scan_blob(data, name)
            self.assertEqual([(x["kind"], x["found_as"]) for x in f], [("COMPROMISED_CA_CERT", "script-signature")], name)

    def test_signature_like_text_without_a_certificate_is_harmless(self):
        junk = b"<signature>** SIG ** not base64 at all ~~~~~~~~~~~~~~~~~~~~~~~~</signature>\r\n" \
               b"# SIG # Begin signature block\r\n# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n# SIG # End signature block\r\n"
        self.assertEqual(self.scan_blob(junk, "odd.ps1"), [])

    def test_unclosed_markers_take_linear_time(self):
        # A lazy regex rescans up to 400 KB after every begin marker: this file took minutes before.
        junk = (b"-----BEGIN CERTIFICATE-----\n# SIG # Begin signature block\n<signature>\n'' SIG '' Begin signature block\n"
                * 6000)
        t = time.monotonic()
        self.assertEqual(list(scan.extract_certs(junk, IND, prefilter=False)), [])
        self.assertLess(time.monotonic() - t, 5)

    def test_blocks_match_the_lazy_regex(self):
        # find_blocks must return exactly what the lazy regex it replaces returned, on awkward layouts.
        begin, end = re.compile(b"<b>"), re.compile(b"</b>")
        lazy = re.compile(b"<b>(.{3,10}?)</b>", re.S)
        for data in (b"<b>12</b><b>123</b>", b"<b><b>12345</b>", b"<b>1234567890123</b><b>abc</b>", b"<b>abc</b></b>",
                     b"<b>a</b>bcd</b>", b"x<b>abcd<b>efgh</b>ij</b>", b"<b>" * 5 + b"</b>" * 5, b"<b>abc", b"</b><b>abc</b>"):
            want = [(m.start(), m.group(1)) for m in lazy.finditer(data)]
            got = [(m.start(), body) for m, body in scan.find_blocks(data, begin, end, 3, 10)]
            self.assertEqual(got, want, data)
        rnd = random.Random(2083449)
        for _ in range(3000):
            data = b"".join(rnd.choice((b"<b>", b"</b>", b"x", b"yz", b"<", b"b>")) for _ in range(rnd.randrange(1, 25)))
            want = [(m.start(), m.group(1)) for m in lazy.finditer(data)]
            got = [(m.start(), body) for m, body in scan.find_blocks(data, begin, end, 3, 10)]
            self.assertEqual(got, want, data)

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


def msi_with_decoy(version=3):
    """A decoy signature-like stream ahead of the real ones, declaring a size larger than the file, so that a
    reader with a per-file budget would spend it all before reaching the real \x05DigitalSignature."""
    lay = {}
    blob = bytearray(cfb_writer.build([("\x05DigitalSignatureDecoy", bytes(range(256)) * 64)] + msi_streams(),
                                      version=version, layout=lay))
    struct.pack_into("<Q", blob, lay["entries"][1] + 0x78, 0xFFFFFFFF)
    return bytes(blob)


def msi_with_aliases(version=3, n=150):
    """n extra signature-like streams that all point into the Data stream's chain, each at a different sector:
    reading each one in full would cost (chain length)^2."""
    lay = {}
    streams = msi_streams() + [("\x05DigitalSignature%03d" % i, b"z") for i in range(n)]
    blob = bytearray(cfb_writer.build(streams, version=version, layout=lay))
    data_secs = lay["sectors"][1]                       # streams[1] is "Data"
    for i in range(n):
        struct.pack_into("<IQ", blob, lay["entries"][5 + i] + 0x74, data_secs[i % len(data_secs)], 20480)
    return bytes(blob)


def msi_with_difat_loop(mb=8):
    """A version 3 file padded to `mb` MB whose only DIFAT sector points to itself, with 0xFFFFFFFF FAT and DIFAT
    sectors declared: a reader that trusts those counts builds a FAT of billions of entries."""
    blob = bytearray(cfb_writer.build(msi_streams(), version=3).ljust(mb * 1024 * 1024, b"\x00"))
    x = (len(blob) - 1) // 512 - 1                      # the last sector
    struct.pack_into("<128I", blob, (x + 1) * 512, *([0] * 127 + [x]))
    struct.pack_into("<I", blob, 0x2C, 0xFFFFFFFF)
    struct.pack_into("<II", blob, 0x44, x, 0xFFFFFFFF)
    return bytes(blob)


def msi_with_oversized_signature():
    """\x05DigitalSignature declares 300 MB, far more than the file holds."""
    lay = {}
    blob = bytearray(cfb_writer.build(msi_streams(), version=3, layout=lay))
    struct.pack_into("<Q", blob, lay["entries"][1] + 0x78, 300 * 1024 * 1024)
    return bytes(blob)


class ReadBudget(bytes):
    """bytes that fail the test once a reader takes more than `budget` slices of it."""
    def __new__(cls, data, budget):
        self = super().__new__(cls, data)
        self.left = budget
        return self

    def __getitem__(self, k):
        if isinstance(k, slice):
            self.left -= 1
            if self.left < 0:
                raise AssertionError("the OLE reader read far more than the file structure needs")
        return bytes.__getitem__(self, k)


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


    # Crafted files: the reader must stay linear in the file size and must still find the real signature.
    # Scan-EmudhraRevoked.ps1 ports the same rules; CI checks both scanners on these files (make_samples.py).
    def test_difat_loop_is_bounded(self):
        got = dict(scan.cfb_signature_streams(ReadBudget(msi_with_difat_loop(), 400)))
        self.assertEqual(got["DigitalSignature"], msi_streams()[0][1])

    def test_aliased_chains_are_bounded(self):
        blob = msi_with_aliases()
        got = list(scan.cfb_signature_streams(ReadBudget(blob, 600)))
        self.assertEqual([n for n, _ in got[:2]], ["DigitalSignature", "MsiDigitalSignatureEx"])
        self.assertLessEqual(sum(len(b) for _, b in got[2:]), len(blob), "other streams share a budget of the file size")

    def test_decoy_cannot_starve_the_real_signature(self):
        got = dict(scan.cfb_signature_streams(msi_with_decoy()))
        self.assertEqual(got["DigitalSignature"], msi_streams()[0][1])
        f = self.scan_blob(msi_with_decoy(), "setup.msi")
        self.assertIn(("COMPROMISED_CA_CERT", "OLE stream: DigitalSignature"), [(x["kind"], x["container"]) for x in f])

    def test_real_signature_name_wins_over_an_alias_of_its_chain(self):
        lay = {}
        blob = bytearray(cfb_writer.build([("\x05DigitalSignatureCopy", b"z")] + msi_streams(), version=3, layout=lay))
        alias, real = lay["entries"][1], lay["entries"][2]
        blob[alias + 0x74:alias + 0x80] = blob[real + 0x74:real + 0x80]            # same start and size
        self.assertEqual([n for n, _ in scan.cfb_signature_streams(bytes(blob))], ["DigitalSignature", "MsiDigitalSignatureEx"])

    def test_declared_size_is_clamped_to_the_file(self):
        blob = msi_with_oversized_signature()
        got = dict(scan.cfb_signature_streams(blob))
        self.assertTrue(got["DigitalSignature"].startswith(msi_streams()[0][1]))
        self.assertLessEqual(len(got["DigitalSignature"]), len(blob))
        # The root's own signature streams do not count against the budget, so the second one is still read.
        self.assertEqual(got["MsiDigitalSignatureEx"], msi_streams()[2][1])

    def test_chain_stops_at_first_sector_outside_the_file(self):
        lay = {}
        blob = bytearray(cfb_writer.build(msi_streams(), version=3, layout=lay))
        nsect = (len(blob) - 1) // 512
        self.assertLess(nsect + 2, 128, "the detour sector must still be inside FAT sector 0")
        secs = lay["sectors"][0]
        struct.pack_into("<I", blob, lay["fat_offset"] + 4 * secs[0], nsect + 2)      # leave the file...
        struct.pack_into("<I", blob, lay["fat_offset"] + 4 * (nsect + 2), secs[1])   # ...and come back
        got = dict(scan.cfb_signature_streams(bytes(blob)))
        self.assertEqual(got["DigitalSignature"], msi_streams()[0][1][:512])

    def test_sibling_cycle_terminates(self):
        lay = {}
        blob = bytearray(cfb_writer.build(msi_streams(), version=3, layout=lay))
        for i in (1, 2, 3, 4):
            struct.pack_into("<I", blob, lay["entries"][i] + 0x48, 1)              # every right sibling -> entry 1
        result = []
        t = threading.Thread(target=lambda: result.append(dict(scan.cfb_signature_streams(bytes(blob)))), daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "walking a cyclic sibling tree must terminate")
        self.assertEqual(result[0]["DigitalSignature"], msi_streams()[0][1])

    def test_names_match_ascii_case_insensitively_only(self):
        sig = msi_streams()[0][1]
        blob = cfb_writer.build([("\x05dIgItAlSiGnAtUrE2", sig), ("\x05D\u0130gitalSignature", sig)], version=3)
        self.assertEqual(sorted(dict(scan.cfb_signature_streams(blob))), ["dIgItAlSiGnAtUrE2"])


class TestListCertsAndTimeLimit(ScanBase):
    def run_cli(self, *args):
        r = subprocess.run([sys.executable, SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode("utf-8", "replace")

    def test_missing_path_is_an_error(self):
        missing = os.path.join(tempfile.gettempdir(), "4thehardway-no-such-file.msi")
        for args in (["--no-trust-stores", "--no-processes", "--quiet", "--path", missing], ["--list-certs", missing]):
            rc, out = self.run_cli(*args)
            self.assertEqual(rc, 3, "a typo in a path must not look like a clean result: %s" % args)

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
