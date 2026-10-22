'''
Framework dùng chung cho track C (ECDSA Singer) và track D (ECDH Engine).
Các file sẽ plug vào framework này:
    - signatures/vulnerable_signer.py  -> cắm NonceStrategy lỗi (F1-F4)
    - signatures/rfc6979_signer.py     -> cắm NonceStrategy RFC 6979 (bản vá)
    - validation/strict_validator.py   -> cắm PointValidator v2 (on-curve + subgroup)
    - system-demos/jwt-es256/*.py      -> dùng BaseECDSASigner trên P-256 (ES256)
    - system-demos/ecdh-api/*.py       -> dùng BaseECDHEngine trên toy curve

Nguyên tắc thiết kế Strategy Pattern:
    - `NonceStrategy`   quyết định cách sinh nonce `k` khi ký ECDSA.
    - `PointValidator`  quyết định ECDH Engine có chấp nhận điểm ngang hàng hay không.

Mọi bản ghi sinh ra khớp trường/kiểu dữ liệu trong `data/schema_definition.json`
(D3 cho chữ ký, D4 cho kết quả validate điểm) — xem `to_d3_record` / `to_d4_partial`.

Safety Guardial:
    - Mọi `key_id` phải có tiền tố "LAB-" — không nạp được khóa production.
    - Toán tử điểm/scalar mult trong file này KHÔNG constant-time và KHÔNG che giấu bất kỳ side-channel nào; chỉ dùng cho mục đích nghiên cứu/lab.
'''

from __future__ import annotations

import hashlib
import secrets
import subprocess
import uuid

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

__all__ = [
    "CurveParams",
    "Point",
    "CURVE_REGISTRY",
    "get_curve",
    "curve_from_d1_record",
    "point_add",
    "scalar_mult",
    "point_neg",
    "is_on_curve",
    "NonceStrategy",
    "RandomNonceStrategy",
    "PointValidator",
    "ValidationOutcome",
    "NoValidation",
    "OnCurveValidator",
    "SignatureResult",
    "BaseECDSASigner",
    "ECDHExchangeResult",
    "BaseECDHEngine",
    "new_lab_key_id",
]

# ------------------------------
# Ultity functions
# ------------------------------

LAB_KEY_PREFIX = "LAB-"

def _assert_lab_key_id(key_id: str) -> None:
    # Usage: Chặn mọi key_id không có tiền tố "LAB-"
    if not isinstance(key_id, str) or not key_id.startswith(LAB_KEY_PREFIX):
        raise ValueError(
            f"key_id={key_id} không hợp lệ: phải có tiền tố '{LAB_KEY_PREFIX}'"
        )

def new_lab_key_id(label: str = "key") -> str:
    # Usage: Sinh key_id theo format 'LAB-<label>-<8 hẽ>' dùng cho singer/engine
    return f"{LAB_KEY_PREFIX}{label}-{uuid.uuid4().hex[:8]}"

def now_iso() -> str:
    # Usage: Sinh timestamp ISO 8601 UTC
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def get_git_commit() -> str:
    # Usage: Get short hash của current git commit
    # Fallback '0000000' nếu không có git

    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short = 7", "HEAD"],
            capture_output = True,
            text = True,
            timeout = 2.0,
            check = True
        )
        commit = out.stdout.strip()
        return commit if commit else "0000000"
    except Exception:
        return "0000000"

def _mod_inv (a: int, m: int) -> int:
    return pow(a % m, -1, m)

# ------------------------------
# Curve & Point - Tham số đường cong và điểm
# ------------------------------

Point = Optional[Tuple[int, int]]   # Point trên Oxy: (x, y) hoặc None (điểm vô cực)

@dataclass (frozen = True)
class CurveParams:
    # Tham số domain Weierstrass curve: y^2 = x^3 + a*x + b (mod p)
    # Bậc nhóm n, cofactor h, generator point G = (Gx, Gy)

    name: str
    p: int
    a: int
    b: int
    n: int  # subgroup_n in D1
    h: int  # cofactor_h in D1
    Gx: int
    Gy: int

    @property
    def G(self) -> Point:
        return Point(self.Gx, self.Gy)

    @property
    def n_bits(self) -> int:
        return self.n.bit_length()   

def curve_from_d1_record(d1_record: Dict[str, Any]) -> CurveParams:
    '''
    Create CurveParams từ bản ghi D1 (data/D1_curves.csv)

    Usage:
        - Các field BigIntString (p, a, b, n, h, Gx, Gy) được chuyển từ chuỗi decimal sang int
        - Quy ước lấy trong data/schema_definition.json
    '''

    return CurveParams(
        name = d1_record.get("curve_id", "unnamed-curve"),
        p = int(d1_record["p"]),
        a = int(d1_record["a"]),
        b = int(d1_record["b"]),
        n = int(d1_record["subgroup_n"]),
        h = int(d1_record["subgroup_h"]),
        Gx = int(d1_record["base_point_x"]),
        Gy = int(d1_record["base_point_y"]),
    )

# NIST P-256
_P256 = CurveParams(
    name="P-256",
    p=115792089210356248762697446949407573530086143415290314195533631308867097853951,
    a=115792089210356248762697446949407573530086143415290314195533631308867097853948,  # p - 3
    b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
    n=115792089210356248762697446949407573529996955224135760342422259061068512044369,
    h=1,
    Gx=48439561293906451759052585252797914202762949526041747995844080717082404635286,
    Gy=36134250956749795798585127919587881956611106672985015071877198253568414405109,
)

CURVE_REGISTRY: Dict[str, CurveParams] = {
    "P-256": _P256,
}

def _self_check_registry() -> None:
    # Usage: Tự kiểm mọi curve đã register khi import module

    for curve in CURVE_REGISTRY.values():
        if not is_on_curve(curve, curve.G):
            raise ValueError(f"Điểm G không nằm trên curve {curve.name}")
        if scalar_mult(curve, curve.n, curve.G) is not None:
            raise ValueError(f"Điểm G không có bậc n trên curve {curve.name}")

def get_curve(curve_or_record) -> CurveParams:
    # Usage: Acp curve đã register trong CURVE_REGISTRY
    if isinstance(curve_or_record, CurveParams):
        return curve_or_record
    if isinstance(curve_or_record, str):
        try:
            return CURVE_REGISTRY[curve_or_record]
        except KeyError as exc:
            raise ValueError(f"Curve {curve_or_record} chưa register") from exc

    if isinstance(curve_or_record, dict):
        return curve_from_d1_record(curve_or_record)
    raise TypeError(f"Không thể convert {curve_or_record} sang CurveParams")

def point_add(curve: CurveParams, P: Point, Q: Point) -> Point:
    # Usage: Weierstass point adding
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None
    if P == Q:
        if y1 % curve.p == 0:
            return None
        len = ((3 * x1 * x1 + curve.a) * _mod_inv(2 * y1, curve.p)) % curve.p
    else:
        len = ((y2 - y1) * _mod_inv((x2 - x1) % curve.p, curve.p)) % curve.p
    x3 = (len * len - x1 - x2) % curve.p
    y3 = (len * (x1 - x3) - y1) % curve.p
    return (x3, y3)

def point_neg(curve: CurveParams, P: Point) -> Point:
    # Usage: Weierstass point negation
    if P is None:
        return None
    x, y = P
    return (x, (-y) % curve.p)

def scalar_mult(curve: CurveParams, k: int, P: Point) -> Point:
    # Usage: Weierstass scalar multiplication (double-and-add)
    if k % curve.n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mult(curve, -k, point_neg(curve, P))

    R: Point = None
    Q: Point = P
    while k:
        if k & 1:
            R = point_add(curve, R, Q)
        Q = point_add(curve, Q, Q)
        k >>= 1
    return R


def is_on_curve(curve: CurveParams, P: Point) -> bool:
    # Usage: Check point P có nằm trên curve hay không
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0

_self_check_registry()  # Tự kiểm tra registry khi import module

# ------------------------------
# Nonce Strategy - Track C
# ------------------------------

