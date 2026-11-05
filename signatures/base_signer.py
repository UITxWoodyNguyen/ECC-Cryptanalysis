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
    # Usage: Check point P is on curve ?
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0

_self_check_registry()  # Auto check all registered curves on import

# ------------------------------
# Nonce Strategy - Track C
# ------------------------------

class NonceStrategy(ABC):
    #Strategy Pattern: Create nonce K when signing ECDSA
    name: str = "undefined"
 
    @abstractmethod
    def generate(self, *, curve: CurveParams, private_key: int, msg_hash_int: int) -> int:
        # Return nonce k in [1, n-1] for ECDSA signing
        raise NotImplementedError
 
 
class RandomNonceStrategy(NonceStrategy):
    # Safe
    name = "random_ok"
 
    def generate(self, *, curve: CurveParams, private_key: int, msg_hash_int: int) -> int:
        return 1 + secrets.randbelow(curve.n - 1)

# ------------------------------
# Point Validator - Track D
# ------------------------------
class ValidationOutcome:
    on_curve: Optional[bool]
    in_subgroup: Optional[bool]
    accepted: bool
    reason: str
 
 
class PointValidator(ABC):
    # GUIDE: Strategy Pattern: Decide whether to accept peer point in ECDH Engine
    version: str = "undefined"
 
    @abstractmethod
    def validate(self, curve: CurveParams, point: Point) -> ValidationOutcome:
        raise NotImplementedError
 
 
class NoValidation(PointValidator):
    # GUIDE: v0 — KHÔNG kiểm tra gì cả, chấp nhận mọi điểm ngang hàng (vulnerable)
    version = "v0_none"
 
    def validate(self, curve: CurveParams, point: Point) -> ValidationOutcome:
        return ValidationOutcome(on_curve=None, in_subgroup=None, accepted=True,
                                  reason="no_validation_performed")
 
 
class OnCurveValidator(PointValidator):
    # GUIDE: v1 — Chỉ kiểm tra điểm ngang hàng có nằm trên curve hay không (on-curve check)
    version = "v1_oncurve"
 
    def validate(self, curve: CurveParams, point: Point) -> ValidationOutcome:
        if point is None:
            return ValidationOutcome(False, None, False, "point_at_infinity")
        x, y = point
        if not (0 <= x < curve.p and 0 <= y < curve.p):
            return ValidationOutcome(False, None, False, "coordinate_out_of_range")
        ok = is_on_curve(curve, point)
        return ValidationOutcome(
            on_curve=ok, in_subgroup=None, accepted=ok,
            reason="on_curve_check_passed" if ok else "not_on_curve",
        )

@dataclass
class SignatureResult:
    sig_id: str
    key_id: str
    curve: str
    signer_version: str
    nonce_class: str
    msg_hash: str
    r: str
    s: str
    timestamp: str
    jti: Optional[str] = None
    # Chỉ để calibration/debug nội bộ (C0 trong experimental_design.md) —
    # KHÔNG ghi trường này vào corpus D3 thật.
    k_debug: Optional[str] = field(default=None, repr=False)
 
    def to_d3_record(
        self, *, run_id: str, sig_index: int, source: str, seed: int,
        git_commit: Optional[str] = None, repeated_r: bool = False,
        repeated_r_group_id: Optional[str] = None,
        leaked_bits_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ghép với ngữ cảnh thí nghiệm (run_id, sig_index, ground-truth repeated_r...)
        để ra đúng 1 dòng khớp data/schema_definition.json -> datasets.D3."""
        return {
            "sig_id": self.sig_id,
            "run_id": run_id,
            "key_id": self.key_id,
            "curve": self.curve,
            "signer_version": self.signer_version,
            "nonce_class": self.nonce_class,
            "msg_hash": self.msg_hash,
            "r": self.r,
            "s": self.s,
            "sig_index": sig_index,
            "repeated_r": repeated_r,
            "repeated_r_group_id": repeated_r_group_id,
            "leaked_bits_class": leaked_bits_class,
            "jti": self.jti,
            "source": source,
            "seed": seed,
            "timestamp": self.timestamp,
            "git_commit": git_commit or get_git_commit(),
        }
 
 
class BaseECDSASigner:
    """ECDSA Signer dùng chung. Hành vi "lỗi" hay "đã vá" hoàn toàn nằm ở
    `nonce_strategy` được truyền vào — bản thân class này trung lập."""
 
    def __init__(
        self, curve, private_key: int, key_id: str,
        signer_version: str, nonce_strategy: NonceStrategy,
    ) -> None:
        _assert_lab_key_id(key_id)
        self.curve = get_curve(curve)
        self.d = private_key % self.curve.n
        self.key_id = key_id
        self.signer_version = signer_version
        self.nonce_strategy = nonce_strategy
        self.Q: Point = scalar_mult(self.curve, self.d, self.curve.G)
 
    @property
    def public_key(self) -> Point:
        return self.Q
 
    @staticmethod
    def hash_message(curve: CurveParams, msg: bytes) -> Tuple[int, str]:
        """Trả về (e, msg_hash_hex). e = min(n_bits, 256) bit đầu của SHA-256(msg),
        theo đúng cách ECDSA cắt hash (FIPS 186-5 §6.4)."""
        digest = hashlib.sha256(msg).digest()
        msg_hash_hex = digest.hex()
        e_full = int.from_bytes(digest, "big")
        hash_bits = len(digest) * 8
        n_bits = curve.n.bit_length()
        if hash_bits > n_bits:
            e = e_full >> (hash_bits - n_bits)
        else:
            e = e_full
        return e, msg_hash_hex
 
    def sign(self, msg: bytes, *, jti: Optional[str] = None,
             max_attempts: int = 1000) -> SignatureResult:
        """Ký theo đúng ECDSA chuẩn; vòng lặp while chỉ để loại bỏ các trường hợp
        suy biến hiếm gặp (r=0 hoặc s=0) — KHÔNG phải cơ chế bảo mật."""
        e, msg_hash_hex = self.hash_message(self.curve, msg)
        for _ in range(max_attempts):
            k = self.nonce_strategy.generate(
                curve=self.curve, private_key=self.d, msg_hash_int=e,
            ) % self.curve.n
            if k == 0:
                continue
            R = scalar_mult(self.curve, k, self.curve.G)
            if R is None:
                continue
            r = R[0] % self.curve.n
            if r == 0:
                continue
            s = (_mod_inv(k, self.curve.n) * (e + r * self.d)) % self.curve.n
            if s == 0:
                continue
            return SignatureResult(
                sig_id=f"sig-{uuid.uuid4().hex[:12]}",
                key_id=self.key_id,
                curve=self.curve.name,
                signer_version=self.signer_version,
                nonce_class=self.nonce_strategy.name,
                msg_hash=msg_hash_hex,
                r=str(r),
                s=str(s),
                timestamp=now_iso(),
                jti=jti,
                k_debug=str(k),
            )
        raise RuntimeError(
            f"Không sinh được chữ ký hợp lệ sau {max_attempts} lần thử "
            f"(nonce_strategy={self.nonce_strategy.name} có thể đang lỗi)."
        )
 
    def sign_with_k(self, msg: bytes, k: int, *, jti: Optional[str] = None) -> SignatureResult:
        """Ký với k TƯỜNG MINH — chỉ dùng cho calibration (C0) hoặc để
        vulnerable_signer.py/nonce_reuse_attacker.py dựng kịch bản tái dùng k có chủ đích.
        KHÔNG dùng hàm này trong đường dẫn signer production-like."""
        e, msg_hash_hex = self.hash_message(self.curve, msg)
        k %= self.curve.n
        if k == 0:
            raise ValueError("k=0 không hợp lệ.")
        R = scalar_mult(self.curve, k, self.curve.G)
        if R is None:
            raise ValueError("k sinh ra điểm vô cực, chọn k khác.")
        r = R[0] % self.curve.n
        s = (_mod_inv(k, self.curve.n) * (e + r * self.d)) % self.curve.n
        if r == 0 or s == 0:
            raise ValueError("k sinh ra r=0 hoặc s=0, chọn k khác.")
        return SignatureResult(
            sig_id=f"sig-{uuid.uuid4().hex[:12]}",
            key_id=self.key_id,
            curve=self.curve.name,
            signer_version=self.signer_version,
            nonce_class=self.nonce_strategy.name,
            msg_hash=msg_hash_hex,
            r=str(r),
            s=str(s),
            timestamp=now_iso(),
            jti=jti,
            k_debug=str(k),
        )
 
    @staticmethod
    def verify(curve, public_key: Point, msg: bytes, r: int, s: int) -> bool:
        """Verifier độc lập — KHÔNG dùng lại private_key, chỉ dùng public_key.
        Dùng làm 'verifier tham chiếu' để tự kiểm mọi chữ ký sinh ra (C0)."""
        curve = get_curve(curve)
        if public_key is None:
            return False
        if not (1 <= r < curve.n and 1 <= s < curve.n):
            return False
        e, _ = BaseECDSASigner.hash_message(curve, msg)
        w = _mod_inv(s, curve.n)
        u1 = (e * w) % curve.n
        u2 = (r * w) % curve.n
        X = point_add(
            curve,
            scalar_mult(curve, u1, curve.G),
            scalar_mult(curve, u2, public_key),
        )
        if X is None:
            return False
        return (X[0] % curve.n) == (r % curve.n)
 
 
# ---------------------------------------------------------------------------
# 5. ECDH Engine
# ---------------------------------------------------------------------------
 
@dataclass
class ECDHExchangeResult:
    accepted: bool
    shared_secret_hash: Optional[str]
    on_curve: Optional[bool]
    in_subgroup: Optional[bool]
    validator_version: str
    reason: str
 
    def to_d4_partial(
        self, *, curve_id: str, point_class: str, x: Optional[int], y: Optional[int],
        run_id: str, seed: int, source_curve_id: Optional[str] = None,
        point_order: Optional[int] = None, oracle_type: str = "na",
        expected_result: Optional[str] = None, git_commit: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ghép kết quả engine (on_curve/accepted) với ground-truth do corpus/attacker
        cung cấp (point_class, point_order, expected_result...) ra 1 dòng D4.
        `match` tự tính nếu expected_result được cung cấp."""
        validator_result = "accept" if self.accepted else "reject"
        match = (validator_result == expected_result) if expected_result else None
        return {
            "point_id": f"pt-{uuid.uuid4().hex[:12]}",
            "curve_id": curve_id,
            "source_curve_id": source_curve_id,
            "point_class": point_class,
            "x": str(x) if x is not None else None,
            "y": str(y) if y is not None else None,
            "on_curve": self.on_curve,
            "point_order": str(point_order) if point_order is not None else None,
            "subgroup_class": "in_subgroup" if self.in_subgroup else (
                "small_order" if self.in_subgroup is False else "na"
            ),
            "validator_version": self.validator_version,
            "validator_result": validator_result,
            "expected_result": expected_result,
            "match": match,
            "protocol_result": self.shared_secret_hash,
            "oracle_type": oracle_type,
            "run_id": run_id,
            "seed": seed,
            "timestamp": now_iso(),
            "git_commit": git_commit or get_git_commit(),
        }
 
 
class BaseECDHEngine:
    """ECDH Engine dùng chung. Hành vi "dễ tổn thương" hay "đã vá" hoàn toàn
    nằm ở `validator` được truyền vào (NoValidation / OnCurveValidator /
    StrictValidator từ validation/strict_validator.py)."""
 
    def __init__(self, curve, private_key: int, key_id: str, validator: PointValidator) -> None:
        _assert_lab_key_id(key_id)
        self.curve = get_curve(curve)
        self.d = private_key % self.curve.n
        self.key_id = key_id
        self.validator = validator
        self.Q: Point = scalar_mult(self.curve, self.d, self.curve.G)
 
    @property
    def public_key(self) -> Point:
        return self.Q
 
    def compute_shared_secret(self, peer_point: Point) -> ECDHExchangeResult:
        """Nhận điểm ngang hàng (có thể không hợp lệ/do attacker gửi), validate
        rồi mới tính S = d * peer_point. Chỉ dùng x(S) để sinh shared secret —
        khớp mô tả oracle giá trị (O1) trong docs/experimental_design.md D.3,
        kể cả rủi ro mơ hồ dấu ±."""
        outcome = self.validator.validate(self.curve, peer_point)
        if not outcome.accepted:
            return ECDHExchangeResult(
                accepted=False, shared_secret_hash=None,
                on_curve=outcome.on_curve, in_subgroup=outcome.in_subgroup,
                validator_version=self.validator.version, reason=outcome.reason,
            )
        S = scalar_mult(self.curve, self.d, peer_point)
        if S is None:
            return ECDHExchangeResult(
                accepted=False, shared_secret_hash=None,
                on_curve=outcome.on_curve, in_subgroup=outcome.in_subgroup,
                validator_version=self.validator.version,
                reason="shared_secret_is_infinity",
            )
        n_bytes = (self.curve.p.bit_length() + 7) // 8
        x_bytes = S[0].to_bytes(n_bytes, "big")
        secret_hash = hashlib.sha256(x_bytes).hexdigest()
        return ECDHExchangeResult(
            accepted=True, shared_secret_hash=secret_hash,
            on_curve=outcome.on_curve, in_subgroup=outcome.in_subgroup,
            validator_version=self.validator.version, reason=outcome.reason,
        )
 
 
# ---------------------------------------------------------------------------
# 6. Self-test / demo (chạy: python -m signatures.base_signer)
# ---------------------------------------------------------------------------
 
if __name__ == "__main__":
    import json
 
    print("== Self-test: ECDSA trên P-256 (ES256-style) ==")
    d_signer = 112233445566778899  # toy scalar, chỉ cho self-test
    signer = BaseECDSASigner(
        curve="P-256",
        private_key=d_signer,
        key_id=new_lab_key_id("ecdsa-selftest"),
        signer_version="random_ok",
        nonce_strategy=RandomNonceStrategy(),
    )
    msg = b'{"sub":"alice","role":"user"}'
    sig = signer.sign(msg)
    ok = BaseECDSASigner.verify(signer.curve, signer.public_key, msg, int(sig.r), int(sig.s))
    print("verify(chữ ký hợp lệ) =", ok)
    assert ok, "Verifier tham chiếu phải chấp nhận chữ ký do chính signer tạo ra"
 
    bad_ok = BaseECDSASigner.verify(signer.curve, signer.public_key, msg + b"x", int(sig.r), int(sig.s))
    print("verify(thông điệp bị sửa) =", bad_ok)
    assert not bad_ok
 
    d3_row = sig.to_d3_record(run_id="run-selftest-001", sig_index=0, source="synthetic_corpus", seed=1)
    print("D3 record:", json.dumps(d3_row, indent=2, ensure_ascii=False))
 
    print("\n== Self-test: ECDH trên toy curve (p=97, a=2, b=3, h=2) ==")
    toy = {
        "curve_id": "crv-selftest-01", "p": "97", "a": "2", "b": "3",
        "subgroup_n": "50", "cofactor_h": "2", "base_point_x": "0", "base_point_y": "10",
    }
    toy_curve = curve_from_d1_record(toy)
 
    alice = BaseECDHEngine(toy_curve, private_key=7, key_id=new_lab_key_id("ecdh-alice"),
                            validator=NoValidation())
    bob = BaseECDHEngine(toy_curve, private_key=13, key_id=new_lab_key_id("ecdh-bob"),
                          validator=NoValidation())
 
    res_valid = alice.compute_shared_secret(bob.public_key)
    print("Alice nhận điểm hợp lệ của Bob -> accepted =", res_valid.accepted,
          "hash =", res_valid.shared_secret_hash)
 
    small_order_point = (3, 6)  # bậc 5 trên chính curve này (xem curves/toy_check.py)
    res_v0 = alice.compute_shared_secret(small_order_point)
    print("[v0_none]      điểm bậc nhỏ (3,6) -> accepted =", res_v0.accepted)
 
    alice_v1 = BaseECDHEngine(toy_curve, private_key=7, key_id=new_lab_key_id("ecdh-alice-v1"),
                               validator=OnCurveValidator())
    res_v1 = alice_v1.compute_shared_secret(small_order_point)
    print("[v1_oncurve]   điểm bậc nhỏ (3,6) -> accepted =", res_v1.accepted,
          "(on_curve nhưng v1 KHÔNG kiểm subgroup -> vẫn accept, minh hoạ cần v2)")
 
    invalid_curve_point = (1, 1)  # không thoả y^2=x^3+2x+3 (mod 97) -> not on curve
    res_wrong = alice_v1.compute_shared_secret(invalid_curve_point)
    print("[v1_oncurve]   điểm sai curve (1,1) -> accepted =", res_wrong.accepted)
 
    d4_row = res_v0.to_d4_partial(
        curve_id=toy_curve.name, point_class="small_subgroup",
        x=3, y=6, point_order=5, run_id="run-d-selftest-001", seed=1,
        expected_result="reject",
    )
    print("D4 record (v0 trên điểm bậc nhỏ):", json.dumps(d4_row, indent=2, ensure_ascii=False))
 
    print("\nSelf-test hoàn tất không lỗi.")