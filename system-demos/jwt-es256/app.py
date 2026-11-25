"""
Vulnerable JWT ES256 Authentication Service (Fixed / Reused ECDSA Nonce k)
--------------------------------------------------------------------------
Mô phỏng dịch vụ cấp phát & xác thực JSON Web Token dùng thuật toán ES256
(ECDSA trên đường cong NIST P-256 + SHA-256, chuẩn RFC 7518 Section 3.4)
nhưng mắc lỗ hổng nghiêm trọng: sử dụng CỐ ĐỊNH một giá trị nonce k cho mọi
lần ký token.

Chỉ cần thu thập 2 JWT hợp lệ bất kỳ từ /auth/login:
  - Hai chữ ký sẽ có cùng thành phần r = (k * G).x mod n
  - Kẻ tấn công khôi phục tức thì k = (z1 - z2) * (s1 - s2)^(-1) mod n
  - Suy ra khóa bí mật ký JWT: d = r^(-1) * (s1 * k - z1) mod n
  - Giả mạo token {"role": "admin"} để truy cập /admin/flag.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from curves.ecc import ECC, Point, FindOrder  # noqa: E402
from signatures.key_storage import save_private_key, load_private_key  # noqa: E402


# Tham số chuẩn NIST P-256 (secp256r1) cho JWT ES256
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def _sha256_int(message: bytes, order_n: int) -> int:
    """Băm SHA-256 và rút gọn theo độ dài bit của bậc nhóm n (chuẩn FIPS 186-4)."""
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    bit_len = order_n.bit_length()
    if len(digest) * 8 > bit_len:
        z >>= (len(digest) * 8 - bit_len)
    return z % order_n


class VulnerableJWTES256Service:
    """Dịch vụ ký/xác thực JWT ES256 với lỗ hổng tái sử dụng nonce k."""

    def __init__(
        self,
        secret_d: int | None = None,
        fixed_nonce_k: int | None = None,
        seed: int = 2026,
        keystore_path: str | Path | None = None,
        keystore_mode: str = "encrypted",
        keystore_passphrase: str = "demo-es256-passphrase",
    ):
        self.curve = ECC(P256_A, P256_B, P256_P)
        self.G = self.curve.find_generator()
        self.order_n = FindOrder(self.G)
        self.rng = random.Random(seed)

        if keystore_path and Path(keystore_path).exists():
            loaded = load_private_key(
                keystore_path,
                passphrase=keystore_passphrase if keystore_mode == "encrypted" else None,
            )
            self.secret_d = loaded["private_d"]
        else:
            self.secret_d = (
                (secret_d % self.order_n)
                if secret_d is not None
                else self.rng.randint(2, self.order_n - 2)
            )
            if keystore_path:
                save_private_key(
                    keystore_path,
                    self.curve,
                    self.secret_d,
                    generator=self.G,
                    order_n=self.order_n,
                    mode=keystore_mode,
                    passphrase=keystore_passphrase if keystore_mode == "encrypted" else None,
                    key_id="jwt-es256-signing-key",
                )

        self.Q_pub = self.secret_d * self.G

        # [VULNERABILITY] Nonce k được khởi tạo một lần duy nhất và tái sử dụng mãi mãi!
        self.fixed_nonce_k = (
            (fixed_nonce_k % self.order_n)
            if fixed_nonce_k is not None
            else self.rng.randint(2, self.order_n - 2)
        )
        self.issued_count = 0

    def sign_es256_raw(self, signing_input: bytes) -> bytes:
        """
        Ký ECDSA trên P-256 trả về 64 bytes (r || s, mỗi thành phần 32 bytes big-endian)
        theo đúng chuẩn JWT ES256 (RFC 7518).
        """
        z = _sha256_int(signing_input, self.order_n)
        k = self.fixed_nonce_k  # <--- LỖI CỐ ĐỊNH NONCE k

        R = k * self.G
        r = R.x % self.order_n
        if r == 0:
            raise RuntimeError("Nonce k tạo ra r = 0")

        k_inv = pow(k, -1, self.order_n)
        s = (k_inv * (z + r * self.secret_d)) % self.order_n
        if s == 0:
            raise RuntimeError("Nonce k tạo ra s = 0")

        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify_es256_raw(self, signing_input: bytes, signature: bytes) -> bool:
        """Xác thực chữ ký JWT ES256 (64 bytes r || s)."""
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if not (1 <= r < self.order_n and 1 <= s < self.order_n):
            return False

        z = _sha256_int(signing_input, self.order_n)
        w = pow(s, -1, self.order_n)
        u1 = (z * w) % self.order_n
        u2 = (r * w) % self.order_n

        P_check = (u1 * self.G) + (u2 * self.Q_pub)
        if P_check.is_infinity:
            return False
        return (P_check.x % self.order_n) == r

    def issue_jwt(self, username: str, role: str = "user", ttl_sec: int = 3600) -> str:
        now = int(time.time())
        header = {"alg": "ES256", "typ": "JWT", "kid": "jwt-es256-signing-key"}
        payload = {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + ttl_sec,
            "jti": f"tok-{self.issued_count + 1}-{self.rng.getrandbits(32):08x}",
        }
        signing_input = f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}".encode("ascii")
        sig = self.sign_es256_raw(signing_input)
        self.issued_count += 1
        return f"{signing_input.decode('ascii')}.{b64url_encode(sig)}"

    def verify_jwt(self, token: str) -> dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError("JWT phải có đủ 3 phần header.payload.signature")

        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(b64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "ES256":
            raise ValueError(f"Thuật toán không được hỗ trợ: {header.get('alg')}")

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = b64url_decode(sig_b64)
        if not self.verify_es256_raw(signing_input, signature):
            raise ValueError("Chữ ký ES256 không hợp lệ")

        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
        if "exp" in payload and int(payload["exp"]) < int(time.time()):
            raise ValueError("JWT đã hết hạn")
        return payload


class JWTES256RequestHandler(BaseHTTPRequestHandler):
    service: VulnerableJWTES256Service

    def log_message(self, format: str, *args: Any) -> None:
        if os.environ.get("JWT_API_VERBOSE") == "1":
            super().log_message(format, *args)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Body JSON phải là object")
        return data

    def _extract_bearer_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ValueError("Thiếu header 'Authorization: Bearer <token>'")
        return auth[len("Bearer "):].strip()

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "alg": "ES256",
                    "nonce_mode": "FIXED_REUSED_NONCE_VULNERABLE",
                    "tokens_issued": self.service.issued_count,
                },
            )
            return

        if self.path == "/jwks":
            byte_len = 32
            x_b64 = b64url_encode(self.service.Q_pub.x.to_bytes(byte_len, "big"))
            y_b64 = b64url_encode(self.service.Q_pub.y.to_bytes(byte_len, "big"))
            self._send_json(
                HTTPStatus.OK,
                {
                    "keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "alg": "ES256",
                            "use": "sig",
                            "kid": "jwt-es256-signing-key",
                            "x": x_b64,
                            "y": y_b64,
                        }
                    ],
                    "curve_params": {
                        "p": str(self.service.curve.p),
                        "a": str(self.service.curve.a),
                        "b": str(self.service.curve.b),
                        "order_n": str(self.service.order_n),
                        "gx": str(self.service.G.x),
                        "gy": str(self.service.G.y),
                        "qx": str(self.service.Q_pub.x),
                        "qy": str(self.service.Q_pub.y),
                    },
                },
            )
            return

        if self.path == "/admin/flag":
            try:
                token = self._extract_bearer_token()
                claims = self.service.verify_jwt(token)
            except Exception as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
                return

            if claims.get("role") != "admin":
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "Access denied: yêu cầu claim role='admin'",
                        "your_claims": claims,
                    },
                )
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ADMIN_ACCESS_GRANTED",
                    "flag": "FLAG{ECDSA_FIXED_NONCE_FORGES_JWT_ES256}",
                    "authenticated_as": claims,
                },
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {self.path}"})

    def do_POST(self) -> None:
        try:
            data = self._read_json()
        except Exception as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"JSON không hợp lệ: {exc}"})
            return

        if self.path == "/auth/login":
            username = str(data.get("username") or "guest").strip()
            # Người dùng thông thường chỉ được cấp quyền "user", không bao giờ được cấp "admin"
            token = self.service.issue_jwt(username=username, role="user")
            self._send_json(
                HTTPStatus.OK,
                {
                    "access_token": token,
                    "token_type": "Bearer",
                    "role": "user",
                },
            )
            return

        if self.path == "/auth/verify":
            token = str(data.get("token") or "")
            try:
                claims = self.service.verify_jwt(token)
                self._send_json(HTTPStatus.OK, {"valid": True, "claims": claims})
            except Exception as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"valid": False, "error": str(exc)})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Unknown endpoint: {self.path}"})


def create_server(
    host: str = "127.0.0.1",
    port: int = 8001,
    secret_d: int | None = None,
    fixed_nonce_k: int | None = None,
    seed: int = 2026,
    keystore_path: str | Path | None = None,
    keystore_mode: str = "encrypted",
) -> tuple[ThreadingHTTPServer, VulnerableJWTES256Service]:
    service = VulnerableJWTES256Service(
        secret_d=secret_d,
        fixed_nonce_k=fixed_nonce_k,
        seed=seed,
        keystore_path=keystore_path,
        keystore_mode=keystore_mode,
    )

    class BoundHandler(JWTES256RequestHandler):
        pass

    BoundHandler.service = service
    server = ThreadingHTTPServer((host, port), BoundHandler)
    return server, service


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerable JWT ES256 Service (Fixed ECDSA Nonce k)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Địa chỉ bind (mặc định: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Cổng HTTP (mặc định: 8001)")
    parser.add_argument("--secret-d", type=lambda s: int(s, 0), default=None, help="Khóa ký d")
    parser.add_argument("--fixed-k", type=lambda s: int(s, 0), default=None, help="Nonce k cố định")
    parser.add_argument("--seed", type=int, default=2026, help="Seed sinh khóa/nonce")
    parser.add_argument("--keystore", default=None, help="Đường dẫn file lưu khóa (tùy chọn)")
    parser.add_argument(
        "--keystore-mode",
        choices=["plaintext", "encrypted"],
        default="encrypted",
        help="Chế độ lưu khóa nếu dùng --keystore",
    )
    args = parser.parse_args()

    server, service = create_server(
        host=args.host,
        port=args.port,
        secret_d=args.secret_d,
        fixed_nonce_k=args.fixed_k,
        seed=args.seed,
        keystore_path=args.keystore,
        keystore_mode=args.keystore_mode,
    )
    print(f"[*] Vulnerable JWT ES256 API listening on http://{args.host}:{args.port}")
    print(f"    - Public Key Q = ({service.Q_pub.x}, {service.Q_pub.y})")
    print(f"    - [DEMO ONLY] Secret d = {service.secret_d}")
    print(f"    - [DEMO ONLY] Fixed  k = {service.fixed_nonce_k}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down JWT ES256 API...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()