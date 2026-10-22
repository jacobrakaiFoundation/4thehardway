# 4thehardway

**Find what still trusts the leaked eMudhra CA keys.**

Find software, certificate stores and certificate files on Linux, macOS and Windows that still contain or chain to the eMudhra intermediate CA keys that were compromised in October 2026.

On 17 October 2026 a researcher reported that the private keys of 8 eMudhra intermediate CAs could be recovered trivially. Mozilla found that every one of the 8 private keys was an integer below 256. The CAs were revoked on 18 and 19 October, and Mozilla and Google are removing trust in `emSign ECC Root CA - G3`. Since then, more than 11,000 certificates signed with the leaked keys have appeared in Certificate Transparency logs. Any client that still trusts the affected roots and does not check revocation will accept them. The incident is tracked in [Mozilla Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).

This tool tells you where those keys still show up on a machine.

- It runs locally, only reads files, and makes **no network connections**.
- `emudhra_scan.py` is one file that needs only Python 3.8 or newer, with nothing to install.
- `Scan-EmudhraRevoked.ps1` is a native PowerShell version for Windows machines without Python. It runs in Windows PowerShell 5.1 and PowerShell 7.

## Quick start

Linux or macOS:

```sh
curl -fsSLO https://raw.githubusercontent.com/jacobrakaiFoundation/4thehardway/main/emudhra_scan.py
python3 emudhra_scan.py            # trust stores + installed programs (a few minutes)
python3 emudhra_scan.py --quick    # trust stores and certificate bundles only (seconds)
sudo python3 emudhra_scan.py --full --json report.json   # every file system
```

Windows, with Python:

```powershell
py emudhra_scan.py
```

Windows, without Python:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/jacobrakaiFoundation/4thehardway/main/Scan-EmudhraRevoked.ps1 -OutFile Scan-EmudhraRevoked.ps1
powershell -ExecutionPolicy Bypass -File .\Scan-EmudhraRevoked.ps1
powershell -ExecutionPolicy Bypass -File .\Scan-EmudhraRevoked.ps1 -Quick
powershell -ExecutionPolicy Bypass -File .\Scan-EmudhraRevoked.ps1 -Path D:\Software -JsonOut report.json
```

Run as administrator or root to see every store and file. Both scanners can check themselves first with `--self-test` or `-SelfTest`.

## What it reports

| Severity | Finding | Meaning |
|---|---|---|
| CRITICAL | `COMPROMISED_CA_CERT` | A certificate for one of the 8 compromised CA keys. This can be the eMudhra-issued certificate, the Sectigo cross-certificate, or any re-encoding of either. |
| CRITICAL | `ISSUED_BY_COMPROMISED_CA` | A certificate signed by one of those CAs, such as a server certificate or the signer of a program. Because the CA keys are public, anyone could have made it. |
| WARNING | `AFFECTED_ROOT` | A root or CA that anchors or issued the compromised CAs, found in a trust store, a bundle, or a program's built-in root list. |
| INFO | any of the above | Found in the Windows `Disallowed` store, which blocks it. This is protective. |

Each finding gives the file or store, the archive member if any, the certificate, and any running processes using that file. Windows also shows the Authenticode signature status. Use `--json` or `-JsonOut` for a machine-readable report.

The exit status is `0` for clean, `1` for warnings only, `2` for critical findings, and `3` for an error.

## What it checks

**Trust stores**
- Windows: every certificate store for the machine and the current user.
- macOS: the system roots, System and login keychains.
- Linux: `/etc/ssl`, `/etc/pki`, `ca-certificates`, NSS databases and `libnssckbi`.
- Everywhere: Firefox and Thunderbird profiles, Java `cacerts`, Python `certifi`, and bundles named by `SSL_CERT_FILE` and similar variables.

**Programs and files.** On Windows these are Program Files, ProgramData, AppData and drivers. On macOS they are `/Applications`, `/Library`, `/usr/local` and `/opt`. On Linux they are `/usr`, `/opt`, `/etc`, `/snap`, Flatpak and `~/.local`. `--full` scans everything instead.
- Signed executables: PE files such as `.exe`, `.dll`, `.sys` and `.msi`, plus `.cab`, `.cat`, Mach-O and ELF.
- PowerShell signature blocks.
- Java, Android and Windows app packages, including nested bundles.
- Certificate files in PEM, DER, PKCS#7, `TRUSTED CERTIFICATE` and JKS formats.
- Certificates embedded in config files, including JSON-escaped PEM.
- Root stores compiled into programs, such as Chromium-based apps, Node and NSS.

## What to do with a finding

- **COMPROMISED_CA_CERT in a trust store or bundle:** remove it, or update the package that ships it, such as `ca-certificates`, `certifi` or a JDK.
- **ISSUED_BY_COMPROMISED_CA on a server certificate:** replace the certificate with one from another CA.
- **ISSUED_BY_COMPROMISED_CA on a signed program:** treat the program as untrusted until you get it from a verified source.
- **AFFECTED_ROOT inside an application:** update the application. Chromium-based apps and tools built before the removal, such as chromedriver, embed a root list that still contains `emSign ECC Root CA - G3`.

## Indicators

The 8 compromised CA keys:

| CA | Use | Key (SPKI SHA-256) |
|---|---|---|
| EM DV TLS CA - G3B | TLS server | `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` |
| EM DV TLS CA - G3C | TLS server | `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` |
| EM OV TLS CA - G3B | TLS server | `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b` |
| EM OV TLS CA - G3C | TLS server | `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` |
| EM EV TLS CA - G3B | TLS server | `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41` |
| EM EV TLS CA - G3C | TLS server | `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` |
| EM OV CS CA - G3B | code signing | `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` |
| EM OV CS CA - G3C | code signing | `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` |

Roots and CAs reported as `AFFECTED_ROOT`:

| Root or CA | Why it matters | Key (SPKI SHA-256) |
|---|---|---|
| emSign ECC Root CA - G3 | Root removed by Mozilla (NSS 3.131.1) and Chrome (Chrome Root Store v43) after the compromise; it anchors the compromised CAs. | `8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782` |
| emSign Root TLS CA - G3 | Directly issued the 6 compromised TLS CAs. Pending (not approved) for Mozilla; cross-signed by emSign ECC Root CA - G3. | `c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9` |
| emSign Root CS CA - G3 | Directly issued the 2 compromised code-signing CAs. | `0a6c2b2ca5b364207954171987ac9d2178561569d8205457e77ca90c32ede282` |

Every certificate behind these values is in [`indicators/certs`](indicators/certs). This includes the emSign-issued certificates, the Sectigo cross-certificates, and a third-party malleated copy of one of them. You can check any key hash yourself:

```sh
openssl x509 -in indicators/certs/EM_DV_TLS_CA_G3B__emsign__42c4accd12c4.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER | sha256sum
```

Matching uses the key, the issuer name and the authority key identifier, not certificate fingerprints. That catches re-issued, cross-signed and re-encoded certificates. Indicators were gathered on 2026-10-22 from CCADB, crt.sh, ctlogs.dev and the bug's attachments.

## Limits

- **Signatures aren't verified.** A certificate counts as issued by a compromised CA when its issuer name or authority key identifier matches. A forgery that changes both would be missed.
- **Default mode picks files by type and location.** Use `--full` or `--path` for anything else.
- **Some formats can't be read**, such as compressed installers (DMG, `.pkg` payloads, NSIS, squashfs images) and password-protected PKCS#12 keystores.
- **Windows downloads trusted roots on demand.** A root that hasn't been used yet may not be in the store.
- **Revocation isn't checked.** The tool doesn't test whether your OS or browser already blocks these CAs through CRLs, OneCRL or CRLSets. It reports where the certificates are.
- **The tool never handles private keys.** It only looks at public certificates.

## Development

```sh
python -m unittest discover -s tests -v   # unit tests (standard library only)
python tools/embed_indicators.py          # after editing indicators/indicators.json
```

CI runs the tests and real scans on Linux, macOS and Windows, using Python 3.9 and 3.13, Windows PowerShell 5.1 and PowerShell 7. Both scanners are checked against the same set of sample files.

This project is not affiliated with eMudhra, Mozilla, Google or Sectigo. It is released under the MIT License.
