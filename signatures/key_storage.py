"""
Secure ECC Key Storage Module (2 Modes: Plaintext vs. Encrypted + Strict ACL)
-----------------------------------------------------------------------------
Dùng chung cho quản lý khóa chữ ký số (ECDSA/EdDSA) và phân tích rủi ro lưu trữ khóa
  - Mode 1 ("plaintext"): Lưu trực tiếp khóa riêng tư d dưới dạng JSON, giữ quyền
    mặc định của OS (minh họa rủi ro lộ khóa khi bị đọc file cục bộ).
  - Mode 2 ("encrypted"): Dẫn xuất khóa qua Scrypt + mã hóa xác thực AES-256-GCM
    kèm AAD ràng buộc tham số đường cong, đồng thời siết quyền tệp 0600 (chỉ chủ sở
    hữu được phép đọc/ghi).
"""

from __future__ import annotations

import base64
import json
import os
import platform
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from curves.ecc import ECC, Point, FindOrder  # noqa: E402


STORAGE_FORMAT_VERSION = "ecc-keystore.v1"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive_aes_key(passphrase: str, salt: bytes, n: int = 1 << 15, r: int = 8, p: int = 1) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase không được để trống ở chế độ 'encrypted'")
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def apply_strict_file_permissions(path: str | Path) -> dict[str, Any]:
    """
    Siết quyền truy cập tệp khóa ở mức hệ điều hành:
      - POSIX (Linux/macOS): chmod 0600 (rw-------)
      - Windows: gỡ kế thừa và chỉ cấp quyền Full Control cho user hiện tại qua icacls
    """
    target = Path(path).resolve()
    system = platform.system()

    if system != "Windows":
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        mode = stat.S_IMODE(target.stat().st_mode)
        return {"os": system, "mode_octal": oct(mode), "strict_ok": mode == 0o600}

    user = os.environ.get("USERNAME") or os.getlogin()
    subprocess.run(
        ["icacls", str(target), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return {"os": system, "owner": user, "strict_ok": True}


def audit_file_permissions(path: str | Path) -> dict[str, Any]:
    """Kiểm tra mức độ an toàn quyền truy cập của file khóa trên đĩa."""
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Không tìm thấy file khóa: {target}")

    system = platform.system()
    if system != "Windows":
        mode = stat.S_IMODE(target.stat().st_mode)
        group_readable = bool(mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP))
        world_readable = bool(mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
        return {
            "path": str(target),
            "os": system,
            "mode_octal": oct(mode),
            "group_accessible": group_readable,
            "world_accessible": world_readable,
            "is_secure_acl": not (group_readable or world_readable),
        }

    out = subprocess.check_output(["icacls", str(target)], text=True, stderr=subprocess.DEVNULL)
    risky = any(token in out for token in ("Everyone", "BUILTIN\\Users", "Authenticated Users"))
    return {
        "path": str(target),
        "os": system,
        "acl_summary": out.strip(),
        "is_secure_acl": not risky,
    }


def save_private_key(
    path: str | Path,
    curve: ECC,
    private_d: int,
    generator: Point | None = None,
    order_n: int | None = None,
    mode: str = "encrypted",
    passphrase: str | None = None,
    key_id: str = "default-ecc-key",
    loose_perm_octal: int = 0o644,
) -> dict[str, Any]:
    """
    Lưu khóa riêng tư ECC ra đĩa theo 1 trong 2 chế độ:
      - mode="plaintext": Lưu trực tiếp d dạng JSON, đặt quyền mặc định (mặc định 0644).
      - mode="encrypted": Mã hóa d bằng AES-256-GCM (khóa từ Scrypt) + siết quyền 0600.
    """
    if mode not in ("plaintext", "encrypted"):
        raise ValueError("mode phải là 'plaintext' hoặc 'encrypted'")

    G = generator or curve.find_generator()
    n = order_n or FindOrder(G)
    if not (1 <= private_d < n):
        raise ValueError("Khóa riêng tư private_d phải nằm trong khoảng [1, n - 1]")

    Q = private_d * G
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    header_meta = {
        "format": STORAGE_FORMAT_VERSION,
        "key_id": key_id,
        "mode": mode,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "curve": {
            "p": str(curve.p),
            "a": str(curve.a),
            "b": str(curve.b),
            "order_n": str(n),
            "gx": str(G.x),
            "gy": str(G.y),
        },
        "public_key": {
            "qx": str(Q.x),
            "qy": str(Q.y),
        },
    }

    if mode == "plaintext":
        document = {
            **header_meta,
            "private_key": {
                "d_int": str(private_d),
                "d_hex": hex(private_d),
            },
        }
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
        if platform.system() != "Windows":
            os.chmod(target, loose_perm_octal)
        perm_info = audit_file_permissions(target)
    else:
        if not passphrase:
            raise ValueError("Bắt buộc cung cấp passphrase khi mode='encrypted'")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        scrypt_params = {"n": 1 << 15, "r": 8, "p": 1}
        aes_key = _derive_aes_key(passphrase, salt, **scrypt_params)

        # Gắn metadata đường cong & public key làm AAD để phát hiện mọi hành vi tráo tham số
        aad = json.dumps(header_meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
        secret_payload = json.dumps({"d": str(private_d)}).encode("utf-8")
        ciphertext = AESGCM(aes_key).encrypt(nonce, secret_payload, aad)

        document = {
            **header_meta,
            "crypto": {
                "kdf": "Scrypt",
                "kdf_params": scrypt_params,
                "salt_b64": _b64e(salt),
                "cipher": "AES-256-GCM",
                "nonce_b64": _b64e(nonce),
                "ciphertext_b64": _b64e(ciphertext),
            },
        }
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
        perm_info = apply_strict_file_permissions(target)

    return {
        "path": str(target),
        "mode": mode,
        "key_id": key_id,
        "permissions": perm_info,
    }


def load_private_key(
    path: str | Path,
    passphrase: str | None = None,
) -> dict[str, Any]:
    """
    Nạp khóa riêng tư và tái tạo đối tượng (ECC, G, Q, d) từ file keystore.
    Tự động xác minh lại Q == d * G sau khi giải mã.
    """
    target = Path(path).resolve()
    document = json.loads(target.read_text(encoding="utf-8"))

    if document.get("format") != STORAGE_FORMAT_VERSION:
        raise ValueError(f"Định dạng keystore không hỗ trợ: {document.get('format')}")

    mode = document["mode"]
    c_meta = document["curve"]
    q_meta = document["public_key"]

    curve = ECC(int(c_meta["a"]), int(c_meta["b"]), int(c_meta["p"]))
    G = Point(curve, int(c_meta["gx"]), int(c_meta["gy"]))
    order_n = int(c_meta["order_n"])

    if mode == "plaintext":
        private_d = int(document["private_key"]["d_int"])
    elif mode == "encrypted":
        if not passphrase:
            raise ValueError("File khóa được mã hóa; cần truyền passphrase để mở khóa")
        crypto_meta = document["crypto"]
        kdf_p = crypto_meta["kdf_params"]
        salt = _b64d(crypto_meta["salt_b64"])
        nonce = _b64d(crypto_meta["nonce_b64"])
        ciphertext = _b64d(crypto_meta["ciphertext_b64"])

        header_meta = {
            "format": document["format"],
            "key_id": document["key_id"],
            "mode": document["mode"],
            "created_at": document["created_at"],
            "curve": c_meta,
            "public_key": q_meta,
        }
        aad = json.dumps(header_meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
        aes_key = _derive_aes_key(
            passphrase, salt, n=int(kdf_p["n"]), r=int(kdf_p["r"]), p=int(kdf_p["p"])
        )
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
        private_d = int(json.loads(plaintext.decode("utf-8"))["d"])
    else:
        raise ValueError(f"Chế độ lưu khóa không hợp lệ: {mode}")

    # Kiểm chứng toàn vẹn khóa công khai sau khi khôi phục
    Q_derived = private_d * G
    Q_stored = Point(curve, int(q_meta["qx"]), int(q_meta["qy"]))
    if Q_derived != Q_stored:
        raise ValueError("Lỗi toàn vẹn khóa: d * G không khớp với public_key lưu trong keystore")

    return {
        "key_id": document["key_id"],
        "mode": mode,
        "curve": curve,
        "generator": G,
        "order_n": order_n,
        "private_d": private_d,
        "public_key": Q_derived,
        "audit": audit_file_permissions(target),
    }


def _selftest() -> None:
    import tempfile

    c = ECC(2, 3, 97)
    G = Point(c, 3, 6)
    n = FindOrder(G)
    d = 4

    with tempfile.TemporaryDirectory() as tmp:
        p_plain = Path(tmp) / "plain_key.json"
        p_enc = Path(tmp) / "enc_key.json"

        save_private_key(p_plain, c, d, generator=G, order_n=n, mode="plaintext", key_id="test-plain")
        save_private_key(
            p_enc, c, d, generator=G, order_n=n, mode="encrypted", passphrase="CorrectHorseBatteryStaple!", key_id="test-enc"
        )

        loaded_plain = load_private_key(p_plain)
        loaded_enc = load_private_key(p_enc, passphrase="CorrectHorseBatteryStaple!")
        assert loaded_plain["private_d"] == d
        assert loaded_enc["private_d"] == d
        assert loaded_enc["audit"]["is_secure_acl"] is True

        # Kiểm tra giải mã sai mật khẩu phải báo lỗi
        failed = False
        try:
            load_private_key(p_enc, passphrase="wrong-password")
        except Exception:
            failed = True
        assert failed, "Giải mã sai mật khẩu phải ném ngoại lệ"

    print("SELFTEST key_storage.py: PASS")


if __name__ == "__main__":
    _selftest()