"""
keysentry/cli.py
────────────────
Command-line interface for KeySentry.

Usage:
    python keysentry.py [OPTIONS]

Author: Prasad
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from keysentry.core import (
    AGE_WARN_DAYS, AGE_CRIT_DAYS, MIN_RSA_BITS,
    SSHKey, audit_paths, default_ssh_dirs, summary_stats,
)
from keysentry.report import export_csv, export_html, export_json

# ── ANSI helpers ─────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def c(text: str, *codes: str) -> str:
    """Apply ANSI codes if color is enabled."""
    if _NO_COLOR:
        return text
    return "".join(codes) + text + RESET


def _risk_color(risk: str) -> str:
    return {
        "LOW":      GREEN,
        "MEDIUM":   YELLOW,
        "HIGH":     ORANGE,
        "CRITICAL": MAGENTA,
    }.get(risk, WHITE)


# ── Header ────────────────────────────────────────────────────────────────────

BANNER = r"""
  _  __          _____            _
 | |/ /___ _   _/ ____|  ___ _ __ | |_ _ __ _   _
 | ' // _ \ | | \___ \ / _ \ '_ \| __| '__| | | |
 | . \  __/ |_| |___) |  __/ | | | |_| |  | |_| |
 |_|\_\___|\__, |____/ \___|_| |_|\__|_|   \__, |
            |___/                           |___/
"""

def print_banner() -> None:
    print(c(BANNER, CYAN, BOLD))
    print(c("  SSH Key Auditor & Expiry Tracker", DIM))
    print(c("  Author: Prasad\n", DIM))


# ── Table rendering ───────────────────────────────────────────────────────────

def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def print_table(keys: list[SSHKey]) -> None:
    if not keys:
        print(c("  No SSH keys found.", YELLOW))
        return

    col_w = [40, 8, 18, 6, 12, 11, 8]
    headers = ["Path", "Type", "Algorithm", "Bits", "Passphrase", "Age", "Risk"]

    # Header row
    header_line = "  " + "  ".join(
        c(h.ljust(col_w[i]), BOLD, WHITE) for i, h in enumerate(headers)
    )
    sep = "  " + c("─" * (sum(col_w) + len(col_w) * 2), DIM)
    print(sep)
    print(header_line)
    print(sep)

    for key in keys:
        path_str  = _truncate(str(key.path), col_w[0])
        type_str  = key.key_type
        alg_str   = _truncate(key.algorithm, col_w[2])
        bits_str  = str(key.bits) if key.bits else "—"
        pass_str  = ("✗ None" if key.has_passphrase is False
                     else "✓ Yes" if key.has_passphrase is True
                     else "—")
        pass_col  = RED if key.has_passphrase is False else GREEN
        age_str   = key.age_label
        risk_str  = key.risk

        row = (
            "  "
            + path_str.ljust(col_w[0]) + "  "
            + type_str.ljust(col_w[1]) + "  "
            + alg_str.ljust(col_w[2])  + "  "
            + bits_str.ljust(col_w[3]) + "  "
            + c(pass_str.ljust(col_w[4]), pass_col) + "  "
            + age_str.ljust(col_w[5])  + "  "
            + c(risk_str.ljust(col_w[6]), _risk_color(risk_str))
        )
        print(row)

        # Print issues indented below the key row
        for issue in key.issues:
            print("  " + c(f"    ⚠  {issue}", YELLOW))

    print(sep)


# ── Summary panel ─────────────────────────────────────────────────────────────

def print_summary(keys: list[SSHKey]) -> None:
    s = summary_stats(keys)
    print()
    print(c("  ── SUMMARY " + "─" * 50, DIM))
    print(f"  Total keys found : {c(str(s['total']), BOLD, WHITE)}")

    def _stat(label: str, val: int, col: str) -> None:
        marker = c("●", col)
        print(f"  {marker} {label:<28} {c(str(val), BOLD, col)}")

    _stat("Critical issues",     s["critical"],      MAGENTA)
    _stat("High issues",         s["high"],          ORANGE)
    _stat("Medium issues",       s["medium"],        YELLOW)
    _stat("Low / clean",         s["low"],           GREEN)
    _stat("No passphrase (priv)",s["no_passphrase"], RED)
    _stat(f"Old keys (>{AGE_WARN_DAYS}d)",  s["old_keys"],      YELLOW)
    _stat("DSA keys (deprecated)",s["dsa_keys"],     RED)
    _stat(f"Weak RSA (<{MIN_RSA_BITS}b)",  s["weak_rsa_keys"], RED)
    print(c("  " + "─" * 60, DIM))
    print()

    # Recommendations
    recs: list[str] = []
    if s["dsa_keys"]:
        recs.append("Replace all DSA keys immediately — they are broken.")
    if s["weak_rsa_keys"]:
        recs.append(f"Upgrade RSA keys to at least {MIN_RSA_BITS} bits.")
    if s["no_passphrase"]:
        recs.append("Add passphrases to unprotected private keys: ssh-keygen -p -f <key>")
    if s["old_keys"]:
        recs.append("Rotate keys older than 1 year.")
    if not recs:
        recs.append("All keys look good! Keep rotating annually.")

    print(c("  Recommendations:", BOLD, CYAN))
    for i, r in enumerate(recs, 1):
        print(f"  {c(str(i) + '.', CYAN)} {r}")
    print()


# ── Argument parsing ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="keysentry",
        description="KeySentry — SSH Key Auditor & Expiry Tracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python keysentry.py                        Scan default ~/.ssh directory
  python keysentry.py --path /etc/ssh -r     Scan /etc/ssh recursively
  python keysentry.py --export report.html   Export HTML report
  python keysentry.py --format json          Output JSON to stdout
  python keysentry.py --risk HIGH            Show only HIGH+ keys
        """,
    )
    p.add_argument(
        "--path", "-p",
        nargs="+",
        metavar="DIR",
        help="Paths to scan (default: ~/.ssh)",
    )
    p.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recurse into subdirectories",
    )
    p.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument(
        "--export", "-e",
        metavar="FILE",
        help="Export report to file (.html, .json, .csv)",
    )
    p.add_argument(
        "--risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        metavar="LEVEL",
        help="Filter: show only keys at or above this risk level",
    )
    p.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip summary panel",
    )
    p.add_argument(
        "--version",
        action="version",
        version="KeySentry 1.0.0",
    )
    return p


_RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.format == "table":
        print_banner()

    # Resolve scan paths
    scan_paths: list[Path] = []
    if args.path:
        for p in args.path:
            resolved = Path(p).expanduser().resolve()
            if not resolved.exists():
                print(c(f"  Warning: path does not exist: {p}", YELLOW))
            else:
                scan_paths.append(resolved)
    if not scan_paths:
        scan_paths = default_ssh_dirs()
        if not scan_paths:
            print(c("  No SSH directories found. Use --path to specify one.", RED))
            return 1

    _info = print if args.format == "table" else lambda *a, **k: print(*a, **k, file=__import__("sys").stderr)
    _info(c(f"  Scanning: {', '.join(str(p) for p in scan_paths)}", DIM))
    if args.recursive:
        _info(c("  Mode: recursive", DIM))
    _info("")

    # Audit
    keys = audit_paths(scan_paths, recursive=args.recursive)

    if not keys:
        print(c("  No SSH keys found in the specified paths.", YELLOW))
        return 0

    # Filter by risk
    if args.risk:
        min_level = _RISK_ORDER[args.risk]
        keys = [k for k in keys if _RISK_ORDER[k.risk] >= min_level]
        if not keys:
            print(c(f"  No keys at risk level {args.risk} or above.", GREEN))
            return 0

    # Sort: highest risk first, then by age
    keys.sort(key=lambda k: (-_RISK_ORDER[k.risk], -k.age_days))

    # ── Output ────────────────────────────────────────────────────────────────
    if args.format == "json":
        print(export_json(keys))
    elif args.format == "csv":
        print(export_csv(keys))
    else:
        print_table(keys)
        if not args.no_summary:
            print_summary(keys)

    # ── Export ────────────────────────────────────────────────────────────────
    if args.export:
        out = Path(args.export)
        suffix = out.suffix.lower()
        if suffix == ".html":
            export_html(keys, out)
            print(c(f"  ✓ HTML report saved to {out}", GREEN))
        elif suffix == ".json":
            export_json(keys, out)
            print(c(f"  ✓ JSON report saved to {out}", GREEN))
        elif suffix == ".csv":
            export_csv(keys, out)
            print(c(f"  ✓ CSV report saved to {out}", GREEN))
        else:
            # Auto-detect from content
            export_html(keys, out)
            print(c(f"  ✓ Report saved to {out}", GREEN))

    critical_count = sum(1 for k in keys if k.risk == "CRITICAL")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
