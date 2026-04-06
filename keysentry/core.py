"""
keysentry/core.py
─────────────────
Core SSH key parsing, analysis, and auditing logic.
100% Python stdlib — no external dependencies.

Author: Prasad
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import platform
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

KEY_EXTENSIONS = {".pub", ""}          # public keys have .pub; private have none
PRIVATE_KEY_HEADERS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
]
PUBLIC_KEY_PREFIXES = [
    "ssh-rsa", "ssh-dss", "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
]

ALGORITHM_SECURITY = {
    "ssh-rsa":                    "rsa",
    "ssh-dss":                    "dsa",
    "ssh-ed25519":                "ed25519",
    "ecdsa-sha2-nistp256":        "ecdsa-256",
    "ecdsa-sha2-nistp384":        "ecdsa-384",
    "ecdsa-sha2-nistp521":        "ecdsa-521",
    "sk-ssh-ed25519@openssh.com": "ed25519-sk",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ecdsa-256-sk",
}

# Minimum acceptable RSA key size (bits)
MIN_RSA_BITS = 2048

# Age thresholds (days)
AGE_WARN_DAYS  = 365
AGE_CRIT_DAYS  = 730


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SSHKey:
    path: Path
    key_type: str           # "public" | "private"
    algorithm: str          # e.g. "ssh-rsa", "ssh-ed25519"
    bits: Optional[int]     # key size in bits (None if unknown / not applicable)
    fingerprint_md5:  str   # MD5 fingerprint  (AA:BB:CC:...)
    fingerprint_sha256: str # SHA-256 fingerprint (SHA256:xxxx)
    comment: str            # comment field from public key
    has_passphrase: Optional[bool]  # None = unknown (public key)
    age_days: int           # days since file last modified
    last_modified: date
    issues: list[str] = field(default_factory=list)
    risk: str = "LOW"       # LOW | MEDIUM | HIGH | CRITICAL

    @property
    def age_label(self) -> str:
        if self.age_days < 365:
            return f"{self.age_days}d"
        years = self.age_days // 365
        days  = self.age_days % 365
        return f"{years}y {days}d" if days else f"{years}y"

    @property
    def risk_color_ansi(self) -> str:
        return {
            "LOW":      "\033[92m",   # green
            "MEDIUM":   "\033[93m",   # yellow
            "HIGH":     "\033[91m",   # red
            "CRITICAL": "\033[95m",   # magenta
        }.get(self.risk, "\033[0m")

    def to_dict(self) -> dict:
        return {
            "path":               str(self.path),
            "key_type":           self.key_type,
            "algorithm":          self.algorithm,
            "bits":               self.bits,
            "fingerprint_md5":    self.fingerprint_md5,
            "fingerprint_sha256": self.fingerprint_sha256,
            "comment":            self.comment,
            "has_passphrase":     self.has_passphrase,
            "age_days":           self.age_days,
            "last_modified":      str(self.last_modified),
            "issues":             self.issues,
            "risk":               self.risk,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Key file discovery
# ─────────────────────────────────────────────────────────────────────────────

def default_ssh_dirs() -> list[Path]:
    """Return default SSH key search paths for the current OS."""
    dirs = []
    home = Path.home()
    dirs.append(home / ".ssh")
    if platform.system() == "Windows":
        # OpenSSH for Windows also uses %USERPROFILE%\.ssh
        prog = Path(os.environ.get("ProgramData", "C:\\ProgramData"))
        dirs.append(prog / "ssh")
    return [d for d in dirs if d.exists()]


def discover_keys(paths: list[Path], recursive: bool = False) -> Iterator[Path]:
    """Yield candidate SSH key file paths from given directories."""
    visited: set[Path] = set()

    def _scan(directory: Path) -> Iterator[Path]:
        try:
            entries = list(directory.iterdir())
        except PermissionError:
            return
        for entry in entries:
            try:
                real = entry.resolve()
                if real in visited:
                    continue
                visited.add(real)
                if entry.is_symlink() and not entry.exists():
                    continue
                if entry.is_dir() and recursive:
                    yield from _scan(entry)
                elif entry.is_file():
                    if _looks_like_ssh_key(entry):
                        yield entry
            except (PermissionError, OSError):
                continue

    for p in paths:
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from _scan(p)


def _looks_like_ssh_key(path: Path) -> bool:
    """Quick heuristic: check filename patterns and first bytes."""
    name = path.name.lower()
    # Known public key suffixes
    if name.endswith(".pub"):
        return True
    # Known private key names
    if name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                "id_ecdsa_sk", "id_ed25519_sk", "identity"}:
        return True
    # Files named like id_rsa_work, id_ed25519_github, etc.
    if re.match(r"^id_[a-z0-9_]+$", name):
        return True
    # Peek at first line
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            first = f.readline(80)
        if any(first.startswith(p) for p in PUBLIC_KEY_PREFIXES):
            return True
        if any(h in first for h in ("BEGIN RSA", "BEGIN EC ", "BEGIN DSA",
                                     "BEGIN OPENSSH", "BEGIN PRIVATE")):
            return True
    except OSError:
        pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Public key parsing (pure Python — no cryptography library)
# ─────────────────────────────────────────────────────────────────────────────

def _decode_mpint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode an SSH mpint from data at offset. Returns (value, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Buffer too short for mpint length")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        raise ValueError("Buffer too short for mpint value")
    value = int.from_bytes(data[offset:offset + length], "big")
    return value, offset + length


def _decode_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Decode an SSH length-prefixed string. Returns (bytes, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Buffer too short for string length")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        raise ValueError("Buffer too short for string value")
    return data[offset:offset + length], offset + length


def _rsa_key_bits_from_blob(blob: bytes) -> int:
    """Extract RSA modulus bit-length from raw key blob."""
    try:
        # blob: string(key-type) | mpint(e) | mpint(n)
        _, offset = _decode_string(blob, 0)   # skip key type
        _, offset = _decode_mpint(blob, offset)  # skip e
        n, _     = _decode_mpint(blob, offset)
        return n.bit_length()
    except Exception:
        return 0


def _ecdsa_bits_from_algorithm(alg: str) -> int:
    if "nistp521" in alg: return 521
    if "nistp384" in alg: return 384
    if "nistp256" in alg: return 256
    return 0


def _fingerprint_from_blob(blob: bytes) -> tuple[str, str]:
    """Return (md5_fingerprint, sha256_fingerprint) from raw base64-decoded blob."""
    md5_raw = hashlib.md5(blob).digest()
    md5_str = ":".join(f"{b:02x}" for b in md5_raw)

    sha256_raw = hashlib.sha256(blob).digest()
    sha256_str = "SHA256:" + base64.b64encode(sha256_raw).decode().rstrip("=")

    return md5_str, sha256_str


def parse_public_key_line(line: str) -> tuple[str, int, str, str, str]:
    """
    Parse a single authorized_keys / id_xxx.pub line.
    Returns (algorithm, bits, fingerprint_md5, fingerprint_sha256, comment).
    Raises ValueError on failure.
    """
    line = line.strip()
    parts = line.split(None, 2)
    if len(parts) < 2:
        raise ValueError("Not a valid public key line")

    alg  = parts[0]
    b64  = parts[1]
    comment = parts[2].strip() if len(parts) == 3 else ""

    if alg not in ALGORITHM_SECURITY:
        raise ValueError(f"Unknown algorithm: {alg}")

    try:
        blob = base64.b64decode(b64)
    except Exception as exc:
        raise ValueError(f"Base64 decode failed: {exc}") from exc

    fp_md5, fp_sha256 = _fingerprint_from_blob(blob)

    bits = 0
    if alg == "ssh-rsa":
        bits = _rsa_key_bits_from_blob(blob)
    elif alg.startswith("ecdsa"):
        bits = _ecdsa_bits_from_algorithm(alg)
    elif alg in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        bits = 256  # Ed25519 always 256-bit equivalent

    return alg, bits, fp_md5, fp_sha256, comment


# ─────────────────────────────────────────────────────────────────────────────
# Private key analysis
# ─────────────────────────────────────────────────────────────────────────────

def _private_key_has_passphrase(path: Path) -> Optional[bool]:
    """
    Detect whether a private key file is encrypted (has passphrase).
    Works by reading the PEM headers — no external tools needed.
    """
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    # OpenSSH new format
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in content:
        # Decode the body and check for "none" cipher (unencrypted)
        try:
            body = re.search(
                r"-----BEGIN OPENSSH PRIVATE KEY-----\s*(.*?)\s*-----END OPENSSH PRIVATE KEY-----",
                content, re.DOTALL
            )
            if body:
                raw = base64.b64decode(body.group(1).replace("\n", "").replace("\r", ""))
                # Magic: "openssh-key-v1\0"
                if raw[:15] == b"openssh-key-v1\x00":
                    offset = 15
                    cipher, offset = _decode_string(raw, offset)
                    return cipher != b"none"
        except Exception:
            pass
        # Fallback: look for encryption hint in text
        return "aes" in content.lower() or "3des" in content.lower()

    # Legacy PEM format
    if "Proc-Type: 4,ENCRYPTED" in content or "DEK-Info:" in content:
        return True
    if any(h in content for h in ("BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY",
                                   "BEGIN DSA PRIVATE KEY")):
        return False  # no encryption header found

    return None


def _private_key_algorithm(path: Path) -> str:
    """Best-effort algorithm detection from private key file."""
    try:
        first_line = path.read_text(encoding="utf-8", errors="ignore").split("\n")[0]
    except OSError:
        return "unknown"
    if "RSA"      in first_line: return "ssh-rsa"
    if "EC "      in first_line: return "ecdsa"
    if "DSA"      in first_line: return "ssh-dss"
    if "OPENSSH"  in first_line: return "openssh"
    return "unknown"


def _private_key_bits(path: Path, algorithm: str) -> Optional[int]:
    """
    Try to extract bit size from private key using ssh-keygen if available,
    otherwise return None.
    """
    try:
        result = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Output: "2048 SHA256:xxx comment (RSA)"
            m = re.match(r"^(\d+)\s+", result.stdout.strip())
            if m:
                return int(m.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Key age
# ─────────────────────────────────────────────────────────────────────────────

def _key_age(path: Path) -> tuple[int, date]:
    """Return (age_days, last_modified_date)."""
    try:
        mtime = path.stat().st_mtime
        last_modified = date.fromtimestamp(mtime)
        age_days = (date.today() - last_modified).days
        return max(age_days, 0), last_modified
    except OSError:
        return 0, date.today()


# ─────────────────────────────────────────────────────────────────────────────
# Issue detection & risk scoring
# ─────────────────────────────────────────────────────────────────────────────

def _assess(key: SSHKey) -> None:
    """Populate key.issues and key.risk in-place."""
    issues = []
    score  = 0   # higher = worse

    alg = key.algorithm.lower()

    # Algorithm-level checks
    if "dss" in alg or "dsa" in alg:
        issues.append("DSA keys are deprecated and considered insecure (NIST removed in 2023)")
        score += 40

    if alg == "ssh-rsa":
        if key.bits is not None:
            if key.bits < 1024:
                issues.append(f"RSA key is critically small ({key.bits} bits) — unusable")
                score += 50
            elif key.bits < MIN_RSA_BITS:
                issues.append(f"RSA key is weak ({key.bits} bits) — minimum recommended is {MIN_RSA_BITS}")
                score += 30
        issues.append("RSA is aging — consider migrating to Ed25519")
        score += 5

    # Age checks
    if key.age_days >= AGE_CRIT_DAYS:
        issues.append(f"Key is {key.age_label} old — strongly consider rotating")
        score += 25
    elif key.age_days >= AGE_WARN_DAYS:
        issues.append(f"Key is {key.age_label} old — rotation recommended")
        score += 10

    # Passphrase check (private keys only)
    if key.key_type == "private" and key.has_passphrase is False:
        issues.append("Private key has NO passphrase — anyone with file access can use it")
        score += 35

    # Risk bucket
    if score >= 60:
        risk = "CRITICAL"
    elif score >= 35:
        risk = "HIGH"
    elif score >= 15:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    key.issues = issues
    key.risk   = risk


# ─────────────────────────────────────────────────────────────────────────────
# Main audit function
# ─────────────────────────────────────────────────────────────────────────────

def audit_key(path: Path) -> Optional[SSHKey]:
    """
    Parse and audit a single key file.
    Returns an SSHKey dataclass or None if file cannot be parsed.
    """
    age_days, last_modified = _key_age(path)

    # ── Public key ──────────────────────────────────────────────────────────
    if path.suffix == ".pub" or _is_public_key(path):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore").strip()
            # Take first non-comment, non-empty line
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    alg, bits, fp_md5, fp_sha256, comment = parse_public_key_line(line)
                    key = SSHKey(
                        path=path,
                        key_type="public",
                        algorithm=alg,
                        bits=bits if bits else None,
                        fingerprint_md5=fp_md5,
                        fingerprint_sha256=fp_sha256,
                        comment=comment,
                        has_passphrase=None,
                        age_days=age_days,
                        last_modified=last_modified,
                    )
                    _assess(key)
                    return key
        except Exception:
            return None
        return None

    # ── Private key ─────────────────────────────────────────────────────────
    if _is_private_key(path):
        alg = _private_key_algorithm(path)
        bits = _private_key_bits(path, alg)
        has_passphrase = _private_key_has_passphrase(path)

        # Try to get fingerprint from paired public key
        pub_path = path.with_suffix(".pub") if path.suffix != ".pub" else None
        fp_md5, fp_sha256 = "n/a", "n/a"
        comment = ""
        if pub_path and pub_path.exists():
            try:
                for line in pub_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        _, _, fp_md5, fp_sha256, comment = parse_public_key_line(line)
                        break
            except Exception:
                pass

        key = SSHKey(
            path=path,
            key_type="private",
            algorithm=alg,
            bits=bits,
            fingerprint_md5=fp_md5,
            fingerprint_sha256=fp_sha256,
            comment=comment,
            has_passphrase=has_passphrase,
            age_days=age_days,
            last_modified=last_modified,
        )
        _assess(key)
        return key

    return None


def _is_public_key(path: Path) -> bool:
    try:
        first = path.read_text(encoding="utf-8", errors="ignore").split("\n")[0]
        return any(first.strip().startswith(p) for p in PUBLIC_KEY_PREFIXES)
    except OSError:
        return False


def _is_private_key(path: Path) -> bool:
    try:
        first = path.read_text(encoding="utf-8", errors="ignore").split("\n")[0]
        return any(h in first for h in ("BEGIN RSA", "BEGIN EC ", "BEGIN DSA",
                                         "BEGIN OPENSSH", "BEGIN PRIVATE"))
    except OSError:
        return False


def audit_paths(
    paths: list[Path],
    recursive: bool = False,
) -> list[SSHKey]:
    """Discover and audit all SSH keys under the given paths."""
    results = []
    seen_fingerprints: set[str] = set()

    for key_path in discover_keys(paths, recursive=recursive):
        key = audit_key(key_path)
        if key is None:
            continue
        # Deduplicate by SHA256 fingerprint (avoid reporting pub+priv as separate)
        dedup_key = key.fingerprint_sha256
        if dedup_key in seen_fingerprints and key.key_type == "public":
            continue
        seen_fingerprints.add(dedup_key)
        results.append(key)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Summary stats
# ─────────────────────────────────────────────────────────────────────────────

def summary_stats(keys: list[SSHKey]) -> dict:
    total    = len(keys)
    critical = sum(1 for k in keys if k.risk == "CRITICAL")
    high     = sum(1 for k in keys if k.risk == "HIGH")
    medium   = sum(1 for k in keys if k.risk == "MEDIUM")
    low      = sum(1 for k in keys if k.risk == "LOW")
    no_pass  = sum(1 for k in keys if k.key_type == "private" and k.has_passphrase is False)
    old      = sum(1 for k in keys if k.age_days >= AGE_WARN_DAYS)
    dsa      = sum(1 for k in keys if "dss" in k.algorithm or "dsa" in k.algorithm)
    weak_rsa = sum(1 for k in keys
                   if k.algorithm == "ssh-rsa" and k.bits is not None and k.bits < MIN_RSA_BITS)

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "no_passphrase": no_pass,
        "old_keys": old,
        "dsa_keys": dsa,
        "weak_rsa_keys": weak_rsa,
    }
