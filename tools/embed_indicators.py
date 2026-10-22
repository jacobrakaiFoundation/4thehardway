#!/usr/bin/env python3
"""Copy indicators/indicators.json and the self-test certificate into both scanners.

Run after editing indicators/indicators.json. With --check, exit 1 if either scanner is out of date.
"""
import glob
import json
import os
import re
import sys

here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data = json.load(open(os.path.join(here, "indicators", "indicators.json"), encoding="utf-8"))
compact = json.dumps(data, separators=(",", ":"), sort_keys=True)
pem_path = sorted(glob.glob(os.path.join(here, "indicators", "certs", "EM_DV_TLS_CA_G3B__emsign__*.pem")))[0]
with open(pem_path, encoding="ascii") as fh:
    pem = fh.read().strip()

targets = {
    "emudhra_scan.py": [
        (r'INDICATORS_JSON = r""".*?"""', 'INDICATORS_JSON = r"""' + compact + '"""'),
        (r'SELFTEST_PEM = b""".*?"""', 'SELFTEST_PEM = b"""\n' + pem + '\n"""'),
    ],
    "Scan-EmudhraRevoked.ps1": [
        (r"\$IndicatorsJson = @'\r?\n.*?\r?\n'@", "$IndicatorsJson = @'\n" + compact + "\n'@"),
        (r"\$SelfTestPem = @'\r?\n.*?\r?\n'@", "$SelfTestPem = @'\n" + pem + "\n'@"),
    ],
}
stale = []
for name, subs in targets.items():
    path = os.path.join(here, name)
    with open(path, encoding="utf-8", newline="") as fh:
        src = fh.read()
    new = src
    for pat, rep in subs:
        new, n = re.subn(pat, lambda m: rep, new, count=1, flags=re.S)
        if n != 1:
            sys.exit("%s: marker not found: %s" % (name, pat))
    if new.replace("\r\n", "\n") != src.replace("\r\n", "\n"):   # ignore CRLF checkouts
        stale.append(name)
        if "--check" not in sys.argv:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
if "--check" in sys.argv:
    if stale:
        print("out of date: " + ", ".join(stale))
    sys.exit(1 if stale else 0)
print("embedded %d compromised CAs and %d roots into: %s" % (len(data["compromised_cas"]), len(data["affected_roots"]),
                                                            ", ".join(stale) or "(already current)"))
