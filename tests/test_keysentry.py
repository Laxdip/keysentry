"""
tests/test_keysentry.py
───────────────────────
Full test suite for KeySentry — no external dependencies required.

Author: Prasadd
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from keysentry.core import (
    SSHKey, _assess, _fingerprint_from_blob, _is_private_key, _is_public_key,
    _key_age, _private_key_has_passphrase, _rsa_key_bits_from_blob,
    audit_key, audit_paths, default_ssh_dirs, discover_keys,
    parse_public_key_line, summary_stats,
)
from keysentry.report import export_csv, export_html, export_json


# ─────────────────────────────────────────────────────────────────────────────
# Helpers to generate real key blobs for testing
# ─────────────────────────────────────────────────────────────────────────────

def _make_ssh_string(s: bytes) -> bytes:
    return struct.pack(">I", len(s)) + s

def _make_mpint(n: int) -> bytes:
    if n == 0:
        return struct.pack(">I", 0)
    length = (n.bit_length() + 8) // 8
    raw = n.to_bytes(length, "big")
    return struct.pack(">I", len(raw)) + raw

def _make_rsa_blob(bits: int) -> bytes:
    """Build a minimal RSA public key blob with a modulus of the given bit-length."""
    e = 65537
    # Fake modulus with the right bit-length
    n = (1 << (bits - 1)) | 1
    blob  = _make_ssh_string(b"ssh-rsa")
    blob += _make_mpint(e)
    blob += _make_mpint(n)
    return blob

def _make_ed25519_blob() -> bytes:
    key_bytes = os.urandom(32)
    blob  = _make_ssh_string(b"ssh-ed25519")
    blob += _make_ssh_string(key_bytes)
    return blob

def _make_pub_line(alg: str, blob: bytes, comment: str = "test@host") -> str:
    b64 = base64.b64encode(blob).decode()
    return f"{alg} {b64} {comment}"

def _write_pub_key(path: Path, alg: str, blob: bytes, comment: str = "test") -> None:
    line = _make_pub_line(alg, blob, comment)
    path.write_text(line + "\n", encoding="utf-8")

def _write_private_key(path: Path, encrypted: bool = False, key_type: str = "RSA") -> None:
    if encrypted:
        content = (
            f"-----BEGIN {key_type} PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,AABBCC\n\n"
            "AAAAAAAAAAAAAAAA\n"
            f"-----END {key_type} PRIVATE KEY-----\n"
        )
    else:
        content = (
            f"-----BEGIN {key_type} PRIVATE KEY-----\n"
            "AAAAAAAAAAAAAAAA\n"
            f"-----END {key_type} PRIVATE KEY-----\n"
        )
    path.write_text(content, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_fingerprint_md5_format():
    blob = b"hello world"
    md5, sha256 = _fingerprint_from_blob(blob)
    assert len(md5.split(":")) == 16
    assert all(len(b) == 2 for b in md5.split(":"))

def test_fingerprint_sha256_prefix():
    blob = b"test data"
    _, sha256 = _fingerprint_from_blob(blob)
    assert sha256.startswith("SHA256:")

def test_fingerprint_deterministic():
    blob = b"same input"
    a = _fingerprint_from_blob(blob)
    b = _fingerprint_from_blob(blob)
    assert a == b

def test_fingerprint_different_blobs():
    f1 = _fingerprint_from_blob(b"blob1")
    f2 = _fingerprint_from_blob(b"blob2")
    assert f1[0] != f2[0]
    assert f1[1] != f2[1]


# ─────────────────────────────────────────────────────────────────────────────
# RSA bit extraction
# ─────────────────────────────────────────────────────────────────────────────

def test_rsa_bits_2048():
    blob = _make_rsa_blob(2048)
    bits = _rsa_key_bits_from_blob(blob)
    assert bits == 2048

def test_rsa_bits_4096():
    blob = _make_rsa_blob(4096)
    bits = _rsa_key_bits_from_blob(blob)
    assert bits == 4096

def test_rsa_bits_1024():
    blob = _make_rsa_blob(1024)
    bits = _rsa_key_bits_from_blob(blob)
    assert bits == 1024

def test_rsa_bits_corrupt_blob():
    bits = _rsa_key_bits_from_blob(b"not a key")
    assert bits == 0


# ─────────────────────────────────────────────────────────────────────────────
# Public key line parsing
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_rsa_4096():
    blob = _make_rsa_blob(4096)
    line = _make_pub_line("ssh-rsa", blob, "user@host")
    alg, bits, fp_md5, fp_sha256, comment = parse_public_key_line(line)
    assert alg == "ssh-rsa"
    assert bits == 4096
    assert comment == "user@host"
    assert ":" in fp_md5
    assert fp_sha256.startswith("SHA256:")

def test_parse_ed25519():
    blob = _make_ed25519_blob()
    line = _make_pub_line("ssh-ed25519", blob, "me@laptop")
    alg, bits, fp_md5, fp_sha256, comment = parse_public_key_line(line)
    assert alg == "ssh-ed25519"
    assert bits == 256
    assert comment == "me@laptop"

def test_parse_invalid_algorithm():
    try:
        parse_public_key_line("ssh-unknown AAAA comment")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unknown algorithm" in str(e)

def test_parse_no_comment():
    blob = _make_ed25519_blob()
    b64  = base64.b64encode(blob).decode()
    line = f"ssh-ed25519 {b64}"
    alg, bits, _, _, comment = parse_public_key_line(line)
    assert alg == "ssh-ed25519"
    assert comment == ""

def test_parse_bad_base64():
    try:
        parse_public_key_line("ssh-ed25519 NOT_VALID_BASE64!!! comment")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# File detection
# ─────────────────────────────────────────────────────────────────────────────

def test_is_public_key_true():
    with tempfile.NamedTemporaryFile(suffix=".pub", mode="w", delete=False) as f:
        blob = _make_ed25519_blob()
        b64  = base64.b64encode(blob).decode()
        f.write(f"ssh-ed25519 {b64} test\n")
        fname = f.name
    try:
        assert _is_public_key(Path(fname))
    finally:
        os.unlink(fname)

def test_is_private_key_rsa():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nAAAAAA\n-----END RSA PRIVATE KEY-----\n")
        fname = f.name
    try:
        assert _is_private_key(Path(fname))
    finally:
        os.unlink(fname)

def test_is_private_key_openssh():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        fname = f.name
    try:
        assert _is_private_key(Path(fname))
    finally:
        os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# Passphrase detection
# ─────────────────────────────────────────────────────────────────────────────

def test_passphrase_detected_encrypted():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES\n\nAAA\n-----END RSA PRIVATE KEY-----\n")
        fname = f.name
    try:
        result = _private_key_has_passphrase(Path(fname))
        assert result is True
    finally:
        os.unlink(fname)

def test_passphrase_detected_unencrypted():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAA\n-----END RSA PRIVATE KEY-----\n")
        fname = f.name
    try:
        result = _private_key_has_passphrase(Path(fname))
        assert result is False
    finally:
        os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# Key age
# ─────────────────────────────────────────────────────────────────────────────

def test_key_age_recent():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        fname = f.name
    try:
        age_days, last_modified = _key_age(Path(fname))
        assert age_days == 0
        assert last_modified == date.today()
    finally:
        os.unlink(fname)

def test_key_age_old():
    import time
    with tempfile.NamedTemporaryFile(delete=False) as f:
        fname = f.name
    try:
        # Set mtime to 400 days ago
        old_time = (date.today() - timedelta(days=400)).timetuple()
        old_ts   = time.mktime(old_time)
        os.utime(fname, (old_ts, old_ts))
        age_days, _ = _key_age(Path(fname))
        assert 398 <= age_days <= 402
    finally:
        os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# Risk assessment
# ─────────────────────────────────────────────────────────────────────────────

def _make_key(algorithm="ssh-ed25519", bits=256, age_days=10,
              has_passphrase=True, key_type="private") -> SSHKey:
    return SSHKey(
        path=Path("/fake/path"),
        key_type=key_type,
        algorithm=algorithm,
        bits=bits,
        fingerprint_md5="aa:bb",
        fingerprint_sha256="SHA256:xxx",
        comment="test",
        has_passphrase=has_passphrase,
        age_days=age_days,
        last_modified=date.today(),
    )

def test_risk_ed25519_clean():
    key = _make_key("ssh-ed25519", 256, 10, True)
    _assess(key)
    assert key.risk == "LOW"
    assert key.issues == []

def test_risk_dsa_critical():
    key = _make_key("ssh-dss", 1024, 10, True)
    _assess(key)
    assert key.risk in ("HIGH", "CRITICAL")
    assert any("DSA" in i for i in key.issues)

def test_risk_weak_rsa():
    key = _make_key("ssh-rsa", 1024, 10, True, "public")
    _assess(key)
    assert key.risk in ("HIGH", "CRITICAL")
    assert any("1024" in i for i in key.issues)

def test_risk_no_passphrase():
    key = _make_key("ssh-rsa", 4096, 10, False, "private")
    _assess(key)
    assert key.risk in ("HIGH", "CRITICAL")
    assert any("passphrase" in i.lower() for i in key.issues)

def test_risk_old_key():
    key = _make_key("ssh-ed25519", 256, 800, True, "private")
    _assess(key)
    assert key.risk in ("MEDIUM", "HIGH", "CRITICAL")
    assert any("old" in i.lower() or "rotat" in i.lower() for i in key.issues)

def test_risk_rsa_2048_ok():
    key = _make_key("ssh-rsa", 2048, 30, True, "public")
    _assess(key)
    # Should not flag weak RSA at 2048
    assert not any("weak" in i.lower() and "2048" in i for i in key.issues)


# ─────────────────────────────────────────────────────────────────────────────
# Full audit_key integration
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_public_key_file():
    with tempfile.TemporaryDirectory() as td:
        pub = Path(td) / "id_ed25519.pub"
        blob = _make_ed25519_blob()
        _write_pub_key(pub, "ssh-ed25519", blob, "user@test")
        key = audit_key(pub)
        assert key is not None
        assert key.key_type == "public"
        assert key.algorithm == "ssh-ed25519"
        assert key.bits == 256
        assert key.fingerprint_sha256.startswith("SHA256:")

def test_audit_rsa_public_key():
    with tempfile.TemporaryDirectory() as td:
        pub = Path(td) / "id_rsa.pub"
        blob = _make_rsa_blob(4096)
        _write_pub_key(pub, "ssh-rsa", blob, "admin@server")
        key = audit_key(pub)
        assert key is not None
        assert key.algorithm == "ssh-rsa"
        assert key.bits == 4096

def test_audit_private_key_no_passphrase():
    with tempfile.TemporaryDirectory() as td:
        priv = Path(td) / "id_rsa"
        _write_private_key(priv, encrypted=False)
        key = audit_key(priv)
        assert key is not None
        assert key.key_type == "private"
        assert key.has_passphrase is False
        assert any("passphrase" in i.lower() for i in key.issues)

def test_audit_private_key_with_passphrase():
    with tempfile.TemporaryDirectory() as td:
        priv = Path(td) / "id_rsa"
        _write_private_key(priv, encrypted=True)
        key = audit_key(priv)
        assert key is not None
        assert key.has_passphrase is True

def test_audit_invalid_file():
    with tempfile.NamedTemporaryFile(suffix=".pub", mode="w", delete=False) as f:
        f.write("this is not a key\n")
        fname = f.name
    try:
        key = audit_key(Path(fname))
        assert key is None
    finally:
        os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────

def test_discover_keys_finds_pub():
    with tempfile.TemporaryDirectory() as td:
        pub = Path(td) / "id_ed25519.pub"
        blob = _make_ed25519_blob()
        _write_pub_key(pub, "ssh-ed25519", blob)
        found = list(discover_keys([Path(td)]))
        assert pub in found

def test_discover_keys_recursive():
    with tempfile.TemporaryDirectory() as td:
        sub = Path(td) / "subdir"
        sub.mkdir()
        pub = sub / "id_ed25519.pub"
        blob = _make_ed25519_blob()
        _write_pub_key(pub, "ssh-ed25519", blob)
        found_no_rec = list(discover_keys([Path(td)], recursive=False))
        found_rec    = list(discover_keys([Path(td)], recursive=True))
        assert pub not in found_no_rec
        assert pub in found_rec

def test_discover_empty_dir():
    with tempfile.TemporaryDirectory() as td:
        found = list(discover_keys([Path(td)]))
        assert found == []

def test_audit_paths_multiple_keys():
    with tempfile.TemporaryDirectory() as td:
        for i, alg in enumerate(["ssh-ed25519", "ssh-rsa"]):
            pub  = Path(td) / f"key{i}.pub"
            blob = _make_ed25519_blob() if alg == "ssh-ed25519" else _make_rsa_blob(2048)
            _write_pub_key(pub, alg, blob, f"user{i}")
        keys = audit_paths([Path(td)])
        assert len(keys) == 2


# ─────────────────────────────────────────────────────────────────────────────
# Summary stats
# ─────────────────────────────────────────────────────────────────────────────

def test_summary_empty():
    s = summary_stats([])
    assert s["total"] == 0
    assert s["critical"] == 0

def test_summary_counts():
    keys = [
        _make_key("ssh-ed25519", 256, 10, True,  "private"),   # LOW
        _make_key("ssh-dss",     1024, 10, True,  "public"),    # HIGH/CRITICAL (DSA)
        _make_key("ssh-rsa",     4096, 10, False, "private"),   # HIGH (no passphrase)
        _make_key("ssh-ed25519", 256, 800, True,  "private"),   # MEDIUM/HIGH (old)
    ]
    for k in keys:
        _assess(k)
    s = summary_stats(keys)
    assert s["total"] == 4
    assert s["dsa_keys"] == 1
    assert s["no_passphrase"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Report exporters
# ─────────────────────────────────────────────────────────────────────────────

def _sample_keys() -> list[SSHKey]:
    keys = [
        _make_key("ssh-ed25519", 256, 10,  True,  "private"),
        _make_key("ssh-rsa",     2048, 400, False, "public"),
        _make_key("ssh-dss",     1024, 100, True,  "public"),
    ]
    for k in keys:
        _assess(k)
    return keys

def test_export_json_valid():
    keys = _sample_keys()
    text = export_json(keys)
    data = json.loads(text)
    assert "summary" in data
    assert "keys" in data
    assert len(data["keys"]) == 3

def test_export_json_to_file():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.json"
        export_json(_sample_keys(), out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["summary"]["total"] == 3

def test_export_csv_has_header():
    text = export_csv(_sample_keys())
    assert "path" in text.lower()
    assert "algorithm" in text.lower()
    lines = text.strip().splitlines()
    assert len(lines) == 4  # header + 3 keys

def test_export_csv_to_file():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.csv"
        export_csv(_sample_keys(), out)
        assert out.exists()
        content = out.read_text()
        assert "ssh-ed25519" in content

def test_export_html_contains_keys():
    keys = _sample_keys()
    html = export_html(keys)
    assert "<!DOCTYPE html>" in html
    assert "ssh-ed25519" in html
    assert "ssh-rsa" in html
    assert "CRITICAL" in html or "HIGH" in html or "MEDIUM" in html

def test_export_html_to_file():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.html"
        export_html(_sample_keys(), out)
        assert out.exists()
        html = out.read_text()
        assert "KeySentry" in html


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────────────────

def test_key_to_dict():
    key = _make_key()
    _assess(key)
    d = key.to_dict()
    assert "path" in d
    assert "algorithm" in d
    assert "risk" in d
    assert isinstance(d["issues"], list)

def test_age_label_days():
    key = _make_key(age_days=45)
    assert "d" in key.age_label

def test_age_label_years():
    key = _make_key(age_days=400)
    assert "y" in key.age_label

def test_comment_empty():
    blob = _make_ed25519_blob()
    b64  = base64.b64encode(blob).decode()
    alg, _, _, _, comment = parse_public_key_line(f"ssh-ed25519 {b64}")
    assert comment == ""

def test_default_ssh_dirs_type():
    dirs = default_ssh_dirs()
    assert isinstance(dirs, list)
    for d in dirs:
        assert isinstance(d, Path)

def test_pub_key_comment_with_spaces():
    blob = _make_ed25519_blob()
    b64  = base64.b64encode(blob).decode()
    line = f"ssh-ed25519 {b64} user name with spaces"
    alg, _, _, _, comment = parse_public_key_line(line)
    assert comment == "user name with spaces"


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback
    passed = failed = 0
    tests  = [(n, f) for n, f in sorted(globals().items())
              if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            passed += 1
            print(f"  \033[92m✓\033[0m {name}")
        except Exception as e:
            failed += 1
            print(f"  \033[91m✗\033[0m {name}: {e}")
            traceback.print_exc()
    print(f"\n── {passed} passed, {failed} failed out of {len(tests)} tests ──")
    sys.exit(0 if failed == 0 else 1)
