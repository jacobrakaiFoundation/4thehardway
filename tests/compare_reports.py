#!/usr/bin/env python3
"""Check a scanner's JSON report against samples/expected.json. Usage: compare_reports.py expected.json report.json"""
import json
import os
import sys

expected = {tuple(x) for x in json.load(open(sys.argv[1]))}
doc = json.load(open(sys.argv[2], encoding="utf-8-sig"))
findings = doc["findings"]
if isinstance(findings, dict):          # PowerShell serializes a single item without the array
    findings = [findings]
got = {(os.path.basename(f["location"]), f.get("container") or None, f["kind"], f["indicator"]) for f in findings}
missing, extra = expected - got, got - expected
for m in sorted(missing, key=str):
    print("MISSING", m)
for e in sorted(extra, key=str):
    print("UNEXPECTED", e)
print("%s: %d expected, %d found, %d missing, %d unexpected" % (sys.argv[2], len(expected), len(got), len(missing), len(extra)))
sys.exit(1 if (missing or extra) else 0)
