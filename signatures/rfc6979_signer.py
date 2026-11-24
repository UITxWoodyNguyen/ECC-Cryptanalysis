"""
signatures/rfc6979_signer.py
===============================

**Deterministic Nonce Generation theo RFC 6979** — bản vá cho mọi failure
mode F1–F4 trong `signatures/vulnerable_signer.py`. Cài đặt đúng thuật toán
ở RFC 6979 §3.2 (HMAC-DRBG dựa trên khóa riêng `x` và hash thông điệp
`H(m)`), được xác minh bằng chính test vector chính thức ở Phụ lục A.2.5
của RFC (xem self-test cuối file).

Vì sao đây là bản vá triệt để (không chỉ "ngẫu nhiên hoá tốt hơn"): `k`
trở thành hàm TẤT ĐỊNH của `(d, H(m))`. Hai thông điệp khác nhau ⇒ hầu như
chắc chắn `k` khác nhau (triệt tiêu toàn bộ 4 lớp lỗi F1–F4); cùng một
thông điệp ký lại ⇒ cùng `k` ⇒ chữ ký giống hệt, không lộ gì thêm — đúng ca
biên 5.1 trong `signatures/nonce_theory.md`. Xem thêm Mục 10 của tài liệu
đó để giải thích đầy đủ.

Trạng thái: DRAFT v0.1 — Tuần 6, owner: Thành viên B.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from typing import Callable

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from signatures.base_signer import NonceStrategy, CurveParams  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "rfc6979_signer.py cần signatures/base_signer.py cùng project-root. "
        f"Lỗi gốc: {exc}"
    ) from exc

__all__ = ["RFC6979NonceStrategy", "generate_k_rfc6979"]


# ---------------------------------------------------------------------------
# 1. Các phép chuyển đổi theo RFC 6979 §2.3 (bits2int, int2octets, bits2octets)
# ---------------------------------------------------------------------------

def _bits2int(data: bytes, qlen: int) -> int:
    """RFC 6979 §2.3.2 — cắt/mở rộng chuỗi bit về đúng qlen bit rồi đọc big-endian.
    Với dữ liệu dài hơn qlen bit: giữ qlen bit TRÁI NHẤT (right-shift phần dư)."""
    x = int.from_bytes(data, "big")
    blen = len(data) * 8
    if blen > qlen:
        x >>= (blen - qlen)
    return x


def _int2octets(x: int, rlen: int) -> bytes:
    """RFC 6979 §2.3.3 — mã hoá big-endian đúng rlen byte (rlen = ceil(qlen/8))."""
    return x.to_bytes(rlen, "big")


def _bits2octets(data: bytes, q: int, qlen: int, rlen: int) -> bytes:
    """RFC 6979 §2.3.4 — bits2int rồi rút gọn mod q, rồi int2octets."""
    z1 = _bits2int(data, qlen)
    z2 = z1 % q  # hợp lệ vì z1 < 2^qlen và q gần 2^qlen (xem ghi chú RFC §2.3.4)
    return _int2octets(z2, rlen)


# ---------------------------------------------------------------------------
# 2. Sinh k theo RFC 6979 §3.2 (HMAC-DRBG)
# ---------------------------------------------------------------------------

def generate_k_rfc6979(
    q: int,
    private_key: int,
    msg_hash_int: int,
    *,
    hash_fn: Callable[..., "hashlib._Hash"] = hashlib.sha256,
    extra_entropy: bytes = b"",
) -> int:
    """Sinh `k` tất định theo đúng 8 bước (a-h) của RFC 6979 §3.2.

    `msg_hash_int`: ĐÃ là kết quả `bits2int(H(m), qlen)` — khớp chính xác
    với `e` mà `BaseECDSASigner.hash_message()` trả về (cùng công thức cắt
    hash, xem `signatures/base_signer.py`), nên không cần hash lại thông
    điệp gốc ở đây; chỉ cần rút gọn mod q để ra `bits2octets(h1)` theo đúng
    định nghĩa RFC (§2.3.4).
    """
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    holen = hash_fn().digest_size

    def hmac_(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hash_fn).digest()

    x_bytes = _int2octets(private_key % q, rlen)
    h1_octets = _int2octets(msg_hash_int % q, rlen)  # = bits2octets(h1) vì msg_hash_int đã là bits2int(h1,qlen)

    V = b"\x01" * holen
    K = b"\x00" * holen
    K = hmac_(K, V + b"\x00" + x_bytes + h1_octets + extra_entropy)
    V = hmac_(K, V)
    K = hmac_(K, V + b"\x01" + x_bytes + h1_octets + extra_entropy)
    V = hmac_(K, V)

    while True:
        T = b""
        while len(T) < rlen:
            V = hmac_(K, V)
            T += V
        k = _bits2int(T, qlen)
        if 1 <= k <= q - 1:
            return k
        # Cực hiếm xảy ra với curve 256-bit trở lên (xác suất ~ (q-1)/2^256)
        K = hmac_(K, V + b"\x00")
        V = hmac_(K, V)


# ---------------------------------------------------------------------------
# 3. NonceStrategy — cắm vào BaseECDSASigner (bản vá cho vulnerable_signer.py)
# ---------------------------------------------------------------------------

class RFC6979NonceStrategy(NonceStrategy):
    """Bản vá: `k` tất định theo RFC 6979, khớp `nonce_class = "deterministic"`
    và `signer_version = "rfc6979"` trong `data/schema_definition.json`.

    `extra_entropy`: tuỳ chọn (RFC 6979 §3.6, biến thể "thêm additional data")
    — để trống (mặc định) cho đúng chuẩn "deterministic (EC)DSA" thuần, chỉ
    đặt khác rỗng nếu cố ý muốn pha thêm 1 nguồn phụ trợ (hiếm khi cần)."""
    name = "deterministic"

    def __init__(self, *, hash_fn: Callable[..., "hashlib._Hash"] = hashlib.sha256,
                 extra_entropy: bytes = b"") -> None:
        self.hash_fn = hash_fn
        self.extra_entropy = extra_entropy

    def generate(self, *, curve: "CurveParams", private_key: int, msg_hash_int: int) -> int:
        return generate_k_rfc6979(
            curve.n, private_key, msg_hash_int,
            hash_fn=self.hash_fn, extra_entropy=self.extra_entropy,
        )


# ---------------------------------------------------------------------------
# 4. Self-test — xác minh bằng TEST VECTOR CHÍNH THỨC của RFC 6979 §A.2.5
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from signatures.base_signer import (  # type: ignore
        BaseECDSASigner, new_lab_key_id, CURVE_REGISTRY,
    )

    print("== 1) Xác minh bằng test vector CHÍNH THỨC RFC 6979 Phụ lục A.2.5 (P-256+SHA-256) ==")
    curve = CURVE_REGISTRY["P-256"]
    x = int("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
    Ux = int("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
    Uy = int("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
    assert curve.Gx and curve.n  # sanity

    # Khóa công khai suy từ x PHẢI khớp Ux,Uy cho trong RFC (tự kiểm trước khi tin k)
    from signatures.base_signer import scalar_mult  # type: ignore
    Q_check = scalar_mult(curve, x, curve.G)
    print("  Public key suy từ x khớp RFC:", Q_check == (Ux, Uy))
    assert Q_check == (Ux, Uy), "Khóa công khai không khớp — kiểm tra lại hằng số x hoặc curve params"

    expected = {
        b"sample": {
            "k": "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
            "r": "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "s": "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        },
        b"test": {
            "k": "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
            "r": "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
            "s": "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
        },
    }

    signer = BaseECDSASigner(
        curve=curve, private_key=x, key_id=new_lab_key_id("rfc6979-kat"),
        signer_version="rfc6979", nonce_strategy=RFC6979NonceStrategy(),
    )

    all_ok = True
    for msg, exp in expected.items():
        e, _ = BaseECDSASigner.hash_message(curve, msg)
        k_got = generate_k_rfc6979(curve.n, x, e)
        sig = signer.sign_with_k(msg, k_got)
        ok_k = (k_got == int(exp["k"], 16))
        ok_r = (int(sig.r) == int(exp["r"], 16))
        ok_s = (int(sig.s) == int(exp["s"], 16))
        print(f"  msg={msg!r}: k khớp={ok_k}, r khớp={ok_r}, s khớp={ok_s}")
        all_ok = all_ok and ok_k and ok_r and ok_s

    assert all_ok, "KHÔNG khớp test vector RFC 6979 — DỪNG, không dùng implementation này"
    print("  => Implementation KHỚP 100% test vector chính thức của RFC.")

    print("\n== 2) Tính chất tất định: ký lại cùng thông điệp ra CÙNG 1 chữ ký ==")
    sig_a = signer.sign(b"deterministic-check")
    sig_b = signer.sign(b"deterministic-check")
    print("  r giống hệt:", sig_a.r == sig_b.r, "| s giống hệt:", sig_a.s == sig_b.s)
    assert sig_a.r == sig_b.r and sig_a.s == sig_b.s

    print("\n== 3) Thông điệp khác nhau -> k khác nhau (không trùng r) ==")
    import secrets
    d2 = secrets.randbelow(2 ** 256)
    signer2 = BaseECDSASigner(curve="P-256", private_key=d2, key_id=new_lab_key_id("rfc6979-vary"),
                               signer_version="rfc6979", nonce_strategy=RFC6979NonceStrategy())
    sigs = [signer2.sign(f"msg-{i}".encode()) for i in range(500)]
    r_values = {s.r for s in sigs}
    print(f"  500 chữ ký, số r khác nhau: {len(r_values)} (kỳ vọng 500 — không trùng)")
    assert len(r_values) == 500

    print("\n== 4) Chữ ký vẫn hợp lệ về mặt mật mã (verify qua public_key, KHÔNG dùng lại x) ==")
    ok_all = all(
        BaseECDSASigner.verify(signer2.curve, signer2.public_key, f"msg-{i}".encode(),
                                int(s.r), int(s.s))
        for i, s in enumerate(sigs)
    )
    print("  verify() pass cho cả 500 chữ ký:", ok_all)
    assert ok_all

    print("\n== 5) RFC 6979 CHẶN được chính nonce_reuse_attacker.py ==")
    from signatures.nonce_reuse_attacker import recover_private_key  # type: ignore
    res = recover_private_key(signer2.curve, sigs, public_key=signer2.public_key)
    print("  Khôi phục được d (kỳ vọng False — không có nhóm r trùng nào để thử):", res.success)
    assert res.success is False

    print("\nSelf-test hoàn tất: mọi assert pass, bao gồm khớp 100% test vector RFC 6979 chính thức.")