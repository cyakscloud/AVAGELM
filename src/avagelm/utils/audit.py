"""Hash-chained JSONL audit logs with Ed25519 signed run manifest."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Iterable


def write_signed_audit(rows: Iterable[dict], output: Path, run_metadata: dict) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    log_path = output / "audit.jsonl"
    previous = "0" * 64
    lines = []
    for row in rows:
        item = {**row, "previous_hash": previous}
        canonical = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        item["record_hash"] = digest
        lines.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        previous = digest
    log_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    log_hash = hashlib.sha256(log_path.read_bytes()).hexdigest()
    manifest = {**run_metadata, "audit_file": log_path.name, "audit_sha256": log_hash,
                "record_count": len(lines), "chain_terminal_hash": previous}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key_path = output / "audit_signing_key.pem"
        if key_path.exists():
            private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        else:
            private = Ed25519PrivateKey.generate()
            key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public = private.public_key()
        msg = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        signature = private.sign(msg)
        manifest["signature_algorithm"] = "Ed25519"
        manifest["public_key_pem"] = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        manifest["signature_base64"] = base64.b64encode(signature).decode()
    except ImportError:
        manifest["signature_algorithm"] = "unavailable"
        manifest["signature_base64"] = None
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_audit(output: Path) -> dict:
    """Verify chain hashes, file digest, and Ed25519 manifest signature."""
    log_path, manifest_path = output / "audit.jsonl", output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    previous, count = "0" * 64, 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        claimed = item.pop("record_hash")
        if item.get("previous_hash") != previous:
            raise ValueError(f"chain discontinuity at record {count + 1}")
        canonical = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if claimed != actual:
            raise ValueError(f"record hash mismatch at record {count + 1}")
        previous, count = claimed, count + 1
    if hashlib.sha256(log_path.read_bytes()).hexdigest() != manifest["audit_sha256"]:
        raise ValueError("audit file digest does not match manifest")
    if count != manifest["record_count"] or previous != manifest["chain_terminal_hash"]:
        raise ValueError("record count or terminal chain hash does not match manifest")
    if manifest.get("signature_algorithm") == "Ed25519":
        from cryptography.hazmat.primitives import serialization
        public = serialization.load_pem_public_key(manifest["public_key_pem"].encode())
        core = {k: v for k, v in manifest.items() if k not in {"signature_algorithm", "public_key_pem", "signature_base64"}}
        message = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        public.verify(base64.b64decode(manifest["signature_base64"]), message)
        signature_status = "valid"
    else:
        signature_status = "unavailable"
    return {"valid": True, "records_verified": count, "signature": signature_status}
