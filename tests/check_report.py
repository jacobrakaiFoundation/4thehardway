#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate a JSON report from either scanner. Used by CI so a crash or a silently empty scan fails.

usage: check_report.py REPORT [--min-certs N] [--min-sources N]
                              [--expect SEVERITY:KIND:INDICATOR:LOCATION_SUBSTRING]... [--forbid-time-limited]

A crash leaves no report (or an unparseable one), so it fails here even though the scanner's exit code
(1 for a Python traceback) overlaps with "warnings found".
"""
import argparse
import json
import re
import sys

SEVERITIES = {"CRITICAL", "WARNING", "INFO"}
KINDS = {"COMPROMISED_CA_CERT", "ISSUED_BY_COMPROMISED_CA", "AFFECTED_ROOT"}


def load_findings(doc):
    f = doc.get("findings")
    if f is None:
        return []
    if isinstance(f, dict):            # PowerShell serializes a one-item array as an object
        return [f]
    return list(f)


def check(path, min_certs=0, min_sources=0, expects=(), forbid_time_limited=False):
    errors = []
    try:
        with open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except Exception as e:
        return ["cannot read report %s: %s" % (path, e)], None
    meta, stats = doc.get("meta") or {}, doc.get("stats") or {}
    if not meta.get("version"):
        errors.append("meta.version missing")
    for k in ("trust_store_sources", "files_scanned", "certificates_parsed"):
        if not isinstance(stats.get(k), int) or stats.get(k) < 0:
            errors.append("stats.%s missing or invalid: %r" % (k, stats.get(k)))
    findings = load_findings(doc)
    for i, f in enumerate(findings):
        if f.get("severity") not in SEVERITIES:
            errors.append("finding %d: bad severity %r" % (i, f.get("severity")))
        if f.get("kind") not in KINDS:
            errors.append("finding %d: bad kind %r" % (i, f.get("kind")))
        sha = (f.get("certificate") or {}).get("sha256") or ""
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            errors.append("finding %d: bad certificate sha256 %r" % (i, sha))
        if not f.get("location"):
            errors.append("finding %d: no location" % i)
    if isinstance(stats.get("certificates_parsed"), int) and stats["certificates_parsed"] < min_certs:
        errors.append("only %d certificates parsed; expected at least %d (are the OS stores being read?)"
                      % (stats["certificates_parsed"], min_certs))
    if isinstance(stats.get("trust_store_sources"), int) and stats["trust_store_sources"] < min_sources:
        errors.append("only %d trust-store sources; expected at least %d" % (stats["trust_store_sources"], min_sources))
    if forbid_time_limited and stats.get("time_limited"):
        errors.append("scan stopped early (time limit)")
    for exp in expects:
        parts = exp.split(":", 3)
        if len(parts) != 4:
            errors.append("bad --expect %r (want SEVERITY:KIND:INDICATOR:LOCATION_SUBSTRING)" % exp)
            continue
        sev, kind, indicator, loc = parts
        if not any(f.get("severity") == sev and f.get("kind") == kind and f.get("indicator") == indicator
                   and loc.lower() in (f.get("location") or "").lower() for f in findings):
            errors.append("expected finding not present: %s" % exp)
    return errors, (doc, findings)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--min-certs", type=int, default=0)
    ap.add_argument("--min-sources", type=int, default=0)
    ap.add_argument("--expect", action="append", default=[])
    ap.add_argument("--forbid-time-limited", action="store_true")
    a = ap.parse_args(argv)
    errors, parsed = check(a.report, a.min_certs, a.min_sources, a.expect, a.forbid_time_limited)
    if parsed:
        doc, findings = parsed
        st = doc.get("stats") or {}
        print("%s: %s certificates parsed, %s trust-store sources, %s files, %d findings%s" % (
            a.report, st.get("certificates_parsed"), st.get("trust_store_sources"), st.get("files_scanned"),
            len(findings), " (time-limited)" if st.get("time_limited") else ""))
        for f in findings:
            print("  %-8s %-24s %-24s %s%s" % (f.get("severity"), f.get("kind"), f.get("indicator"), f.get("location"),
                                              ("  [%s]" % f["container"]) if f.get("container") else ""))
    for e in errors:
        print("FAIL: " + e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
