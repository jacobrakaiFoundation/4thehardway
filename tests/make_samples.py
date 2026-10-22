#!/usr/bin/env python3
"""Write a directory of sample files that both scanners must flag identically (used by CI)."""
import base64
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan import CA_DER, LEAF_DER, BENIGN_DER, pkcs7, rb, indicator_pem, FIX, msi_streams  # noqa: E402
import cfb_writer  # noqa: E402

EXPECTED = [  # (file, container, kind, indicator)
    ("setup.exe", None, "COMPROMISED_CA_CERT", "EM OV CS CA - G3C"),
    ("setup.exe", None, "ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"),
    ("app.jar", "META-INF/CERT.RSA", "ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"),
    ("App.appxbundle", "App_x64.appx!/AppxSignature.p7x", "COMPROMISED_CA_CERT", "EM OV CS CA - G3C"),
    ("script.ps1", None, "COMPROMISED_CA_CERT", "EM OV CS CA - G3C"),
    ("chain.p7b", None, "COMPROMISED_CA_CERT", "EM OV CS CA - G3C"),
    ("config.json", None, "ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"),
    ("server.crt", None, "ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"),
    ("roots.pem", None, "AFFECTED_ROOT", "emSign ECC Root CA - G3"),
    # Fragmented OLE compound file: only found by reassembling the signature streams.
    ("fragmented.msi", "OLE stream: DigitalSignature", "COMPROMISED_CA_CERT", "EM OV CS CA - G3C"),
    ("fragmented.msi", "OLE stream: MsiDigitalSignatureEx", "ISSUED_BY_COMPROMISED_CA", "EM DV TLS CA - G3B"),
]


def main(out):
    os.makedirs(out, exist_ok=True)
    w = lambda name, data: open(os.path.join(out, name), "wb").write(data)
    w("setup.exe", b"MZ" + b"\x00" * 4000 + pkcs7([LEAF_DER, CA_DER]) + b"\x00" * 2000)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("META-INF/CERT.RSA", pkcs7([LEAF_DER]))
    w("app.jar", bio.getvalue())
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AppxSignature.p7x", b"PKCX" + pkcs7([CA_DER]))
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("App_x64.appx", inner.getvalue())
    w("App.appxbundle", outer.getvalue())
    b64 = base64.b64encode(pkcs7([CA_DER])).decode()
    sig = "\r\n".join("# " + b64[i:i + 64] for i in range(0, len(b64), 64))
    w("script.ps1", ("Write-Host hi\r\n# SIG # Begin signature block\r\n" + sig + "\r\n# SIG # End signature block\r\n").encode())
    w("chain.p7b", b"-----BEGIN PKCS7-----\n" + base64.encodebytes(pkcs7([CA_DER, BENIGN_DER])) + b"-----END PKCS7-----\n")
    leaf_pem = rb(os.path.join(FIX, "leaf_dv_g3b_we-have-a-problem.pem"))
    w("config.json", json.dumps({"tls": {"cert": leaf_pem.decode().strip()}}).encode())
    w("server.crt", leaf_pem)
    w("roots.pem", rb(indicator_pem("emSign_ECC_Root_CA_G3__root__")) + rb(os.path.join(FIX, "benign_ISRG_Root_X1.pem")))
    w("clean-bundle.pem", rb(os.path.join(FIX, "benign_ISRG_Root_X1.pem")) + rb(os.path.join(FIX, "nearmiss_EM_DV_TLS_CA_G3A-1.pem")))
    w("fragmented.msi", cfb_writer.build(msi_streams(), version=3))
    w("readme.txt", b"nothing to see")
    with open(os.path.join(out, "expected.json"), "w") as fh:
        json.dump(EXPECTED, fh, indent=1)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
