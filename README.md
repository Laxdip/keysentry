# 🔑 KeySentry — SSH Key Auditor & Expiry Tracker

Scan your system for SSH keys, detect weak algorithms, unprotected private keys, and keys that are overdue for rotation.

**Zero external dependencies — pure Python stdlib.**

---

## Features

- 🔍 **Auto-discovers** SSH keys in `~/.ssh` and system paths
- 🔐 **Passphrase detection** — flags private keys with no passphrase
- ⚠️ **Weak algorithm detection** — DSA (deprecated), RSA < 2048 bits
- 📅 **Age tracking** — warns on keys older than 1 year, critical at 2 years
- 🔑 **Fingerprints** — MD5 and SHA-256 for every key
- 📊 **Reports** — HTML dashboard, JSON, CSV export
- 🖥️ **Cross-platform** — Windows, Linux, macOS
- 🎨 **Color terminal output** with risk levels

---

## Risk Levels

| Level | Meaning |
|---|---|
| 🟢 LOW | Key is healthy |
| 🟡 MEDIUM | Old key, rotation recommended |
| 🟠 HIGH | Weak algorithm or no passphrase |
| 🔴 CRITICAL | DSA key, critically small RSA, or multiple issues |

---

## Quick Start

```bash
# Clone
git clone https://github.com/Laxdip/keysentry.git
cd keysentry

# Run (no install needed)
python run.py

# Scan a specific path
python run.py --path ~/.ssh

# Recursive scan
python run.py --path /etc/ssh --recursive

# Export HTML report
python run.py --export report.html

# Show only HIGH and above
python run.py --risk HIGH

# JSON output
python run.py --format json
```

---

## Usage

```
python run.py [OPTIONS]

Options:
  --path, -p DIR      Path(s) to scan (default: ~/.ssh)
  --recursive, -r     Recurse into subdirectories
  --format, -f        Output format: table | json | csv (default: table)
  --export, -e FILE   Export to file (.html / .json / .csv)
  --risk LEVEL        Filter by minimum risk: LOW | MEDIUM | HIGH | CRITICAL
  --no-summary        Skip the summary panel
  --version           Show version
  --help              Show help
```

---

## Example Output

```
  _  __          _____            _
 | |/ /___ _   _/ ____|  ___ _ __ | |_ _ __ _   _
 | ' // _ \ | | \___ \ / _ \ '_ \| __| '__| | | |
 | . \  __/ |_| |___) |  __/ | | | |_| |  | |_| |
 |_|\_\___|\__, |____/ \___|_| |_|\__|_|   \__, |
            |___/                           |___/

  SSH Key Auditor & Expiry Tracker
  Author: Prasad

  Scanning: /home/user/.ssh

  Path                        Type     Algorithm          Bits  Passphrase  Age     Risk
  ────────────────────────────────────────────────────────────────────────────────────────
  ~/.ssh/id_rsa               private  ssh-rsa            2048  ✗ None      1y 45d  CRITICAL
    ⚠  Private key has NO passphrase
    ⚠  Key is 1y 45d old — rotation recommended
  ~/.ssh/id_ed25519            private  ssh-ed25519        256   ✓ Yes       45d     LOW
  ~/.ssh/old_key.pub           public   ssh-dss            1024  —           3y 2d   CRITICAL
    ⚠  DSA keys are deprecated and considered insecure
    ⚠  Key is 3y 2d old — strongly consider rotating

  ── SUMMARY ─────────────────────────────────────────────────────────
  Total keys found :  3
  ● Critical issues            2
  ● High issues                0
  ● Medium issues              0
  ● Low / clean                1
  ● No passphrase (priv)       1
  ● Old keys (>365d)           2
  ● DSA keys (deprecated)      1
  ● Weak RSA (<2048b)          0
  ────────────────────────────────────────────────────────────────────

  Recommendations:
  1. Replace all DSA keys immediately — they are broken.
  2. Add passphrases to unprotected private keys: ssh-keygen -p -f <key>
  3. Rotate keys older than 1 year.
```

---

## What Gets Checked

| Check | Detail |
|---|---|
| DSA keys | Flagged CRITICAL — broken since 2023 |
| RSA < 2048 bits | Flagged HIGH/CRITICAL |
| RSA < 4096 bits | Suggests migration to Ed25519 |
| No passphrase | Flagged HIGH — private keys are unprotected |
| Age > 1 year | Flagged MEDIUM |
| Age > 2 years | Flagged HIGH |

---

## File Structure

```
keysentry/
├── keysentry/
│   ├── __init__.py     # Package metadata
│   ├── core.py         # Key parsing, analysis, risk scoring
│   ├── cli.py          # CLI + terminal rendering
│   └── report.py       # JSON / CSV / HTML exporters
├── tests/
│   └── test_keysentry.py   # 49 tests (zero external deps)
├── run.py              # Entry point
└── README.md
```

---

## Running Tests

```bash
python tests/test_keysentry.py
```

No pytest needed — runs with pure stdlib.

---

## Requirements

- Python 3.8+
- No external packages
- `ssh-keygen` (optional — used to extract private key bit sizes when available)

---

## Author

Prasad

## License

MIT
