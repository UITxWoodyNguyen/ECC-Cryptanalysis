"""
signatures/nonce_reuse_attacker.py
====================================

**Thuật toán khôi phục khóa riêng `d` từ 2+ chữ ký ECDSA trùng nonce `k`.**

Cài đặt ĐÚNG công thức và pseudocode đã chứng minh trong
`signatures/nonce_theory.md` (Mục 3 — suy ra công thức, Mục 5 — 4 ca biên bắt
buộc xử lý, Mục 7 — pseudocode). File này là thư viện (`.py`, không phải
notebook) vì bị import trực tiếp bởi:

    - `signatures/test_nonce_attack.ipynb`           (thí nghiệm Track C)
    - `system-demos/jwt-es256/recover_key.ipynb`     (tấn công demo thật)

API chính:
    recover_private_key(curve, signatures, public_key=None) -> RecoveryResult
        Nhận MỌI chữ ký quan sát được (không cần tự nhóm theo r trước), tự
        tìm các nhóm trùng r, thử khôi phục d trên từng nhóm, trả kết quả
        tốt nhất kèm "evidence" (những cặp chữ ký đã dùng để kết luận).

Trạng thái: DRAFT v0.1 — Tuần 5-6, owner: Thành viên B.
"""

from __future__ import annotations

import itertools
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# --- Import khung dùng chung từ signatures/base_signer.py -----------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from signatures.base_signer import (  # type: ignore
        CurveParams, Point, get_curve, scalar_mult, _mod_inv,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "nonce_reuse_attacker.py cần signatures/base_signer.py cùng project-root. "
        f"Lỗi gốc: {exc}"
    ) from exc

__all__ = [
    "RecoveryResult",
    "hash_hex_to_e",
    "candidate_ds_from_pair",
    "recover_d_from_pair",
    "recover_private_key",
]


# ---------------------------------------------------------------------------
# 0. Tiện ích: đọc field từ chữ ký, dù là SignatureResult hay dict (bản ghi D3)
# ---------------------------------------------------------------------------

SignatureLike = Union[Any, Dict[str, Any]]  # SignatureResult hoặc dict khớp D3


def _field(sig: SignatureLike, name: str) -> Any:
    """Đọc thuộc tính dù `sig` là dataclass (SignatureResult) hay dict (bản
    ghi D3 từ data/D3_signatures.csv đã parse)."""
    if isinstance(sig, dict):
        return sig[name]
    return getattr(sig, name)


def hash_hex_to_e(curve: "CurveParams", msg_hash_hex: str) -> int:
    """Suy `e` (giá trị hash dùng trong phương trình ECDSA) từ `msg_hash`
    (hex digest SHA-256 ĐẦY ĐỦ, như lưu trong cột `msg_hash` của dataset D3)
    — KHÔNG băm lại thông điệp gốc.

    Phải khớp CHÍNH XÁC cách BaseECDSASigner.hash_message() cắt hash (FIPS
    186-5 §6.4: lấy min(n_bits, hash_bits) bit đầu của digest), vì đây là
    phương trình mà signer đã dùng lúc ký — nếu cắt sai, công thức khôi phục
    ở Mục 3 (nonce_theory.md) sẽ cho `k`, `d` SAI mà không báo lỗi gì cả.
    """
    digest = bytes.fromhex(msg_hash_hex)
    e_full = int.from_bytes(digest, "big")
    hash_bits = len(digest) * 8
    n_bits = curve.n.bit_length()
    if hash_bits > n_bits:
        return e_full >> (hash_bits - n_bits)
    return e_full


# ---------------------------------------------------------------------------
# 1. Công thức lõi — 1 cặp chữ ký đã biết chắc cùng r
# ---------------------------------------------------------------------------

def candidate_ds_from_pair(
    curve: "CurveParams", e_i: int, r: int, s_i: int, e_j: int, s_j: int,
) -> List[int]:
    """Trả về MỌI ứng viên `d` hợp lý từ 1 cặp chữ ký cùng `r`, thử đủ 4 tổ
    hợp dấu `(±s_i, ±s_j)` (ca biên 5.2 — mơ hồ do canonical hoá low-S trong
    `nonce_theory.md`). KHÔNG xác thực bằng public key ở bước này (tách
    riêng để hàm này dùng được cả khi chưa biết Q).

    Trả về list RỖNG nếu cặp suy biến (ca biên 5.1: `e_i==e_j` khiến mọi tổ
    hợp cho `denom=0`)."""
    n = curve.n
    r %= n
    if r == 0:
        return []
    candidates: List[int] = []
    for s_a in (s_i % n, (-s_i) % n):
        for s_b in (s_j % n, (-s_j) % n):
            denom = (s_a - s_b) % n
            if denom == 0:
                continue  # ca biên 5.1 cho tổ hợp dấu này — bỏ qua, thử tổ hợp khác
            k = ((e_i - e_j) * _mod_inv(denom, n)) % n
            if k == 0:
                continue  # k=0 không hợp lệ về mặt chữ ký, loại
            d = ((k * s_a - e_i) * _mod_inv(r, n)) % n
            candidates.append(d)
    # Khử trùng, giữ thứ tự xuất hiện
    seen = set()
    unique = []
    for d in candidates:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def recover_d_from_pair(
    curve: "CurveParams", e_i: int, r: int, s_i: int, e_j: int, s_j: int,
    public_key: Optional["Point"] = None,
) -> Optional[int]:
    """Như `candidate_ds_from_pair`, nhưng nếu có `public_key` thì LỌC lấy
    đúng ứng viên thoả `d·G == Q` (bước xác nhận BẮT BUỘC theo
    nonce_theory.md §7, mục 1) và trả về chính xác giá trị đó.

    Nếu KHÔNG truyền `public_key`, trả về ứng viên đầu tiên tìm được — người
    gọi PHẢI tự xác thực bằng cách khác (vd đối chiếu nhiều cặp — xem
    `recover_private_key`), vì không có gì đảm bảo đây là tổ hợp dấu đúng.
    """
    candidates = candidate_ds_from_pair(curve, e_i, r, s_i, e_j, s_j)
    if not candidates:
        return None
    if public_key is None:
        return candidates[0]
    for d in candidates:
        if scalar_mult(curve, d, curve.G) == public_key:
            return d
    return None


# ---------------------------------------------------------------------------
# 2. Gom nhóm theo r — phiên bản tối giản dùng nội bộ
# ---------------------------------------------------------------------------
#
# LƯU Ý: đây CHỈ là phần gom nhóm tối thiểu để module này tự dùng được ngay
# (dict r -> [chữ ký], O(N)). Bộ dò quét quy mô lớn trên một luồng chữ ký
# liên tục (streaming, nhiều khóa cùng lúc) là việc của
# `signatures/repeated_r_detector.py` — khi file đó có, có thể thay bước này
# bằng kết quả của nó (interface tương thích: dict r -> list chữ ký).

def _normalize_r(sig: SignatureLike) -> str:
    return str(_field(sig, "r"))


def _group_by_r(signatures: Sequence[SignatureLike]) -> Dict[str, List[SignatureLike]]:
    groups: Dict[str, List[SignatureLike]] = defaultdict(list)
    for sig in signatures:
        groups[_normalize_r(sig)].append(sig)
    return {r: sigs for r, sigs in groups.items() if len(sigs) >= 2}


# ---------------------------------------------------------------------------
# 3. Kết quả khôi phục
# ---------------------------------------------------------------------------

@dataclass
class RecoveryResult:
    success: bool
    d: Optional[int] = None
    k: Optional[int] = None
    r_group: Optional[str] = None
    evidence_pairs: List[Tuple[Any, Any]] = field(default_factory=list)
    """Các cặp chữ ký (sig_i, sig_j) thực sự cho ra `d` thắng cuộc — để trích
    dẫn làm bằng chứng trong báo cáo, KHÔNG phải toàn bộ cặp đã thử."""
    candidate_votes: Dict[int, int] = field(default_factory=dict)
    """d_candidate -> số cặp (đã qua xác nhận nếu có public_key, hoặc số cặp
    đồng thuận nếu không có public_key) ủng hộ giá trị đó."""
    verified_by_public_key: bool = False
    groups_examined: int = 0
    pairs_examined: int = 0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "d": str(self.d) if self.d is not None else None,
            "k": str(self.k) if self.k is not None else None,
            "r_group": self.r_group,
            "evidence_pair_count": len(self.evidence_pairs),
            "candidate_votes": {str(k): v for k, v in self.candidate_votes.items()},
            "verified_by_public_key": self.verified_by_public_key,
            "groups_examined": self.groups_examined,
            "pairs_examined": self.pairs_examined,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# 4. Hàm chính — recover_private_key
# ---------------------------------------------------------------------------

def recover_private_key(
    curve_input,
    signatures: Sequence[SignatureLike],
    *,
    public_key: Optional["Point"] = None,
    max_pairs_per_group: int = 66,  # = C(12,2) — đủ cho đa số phiếu, tránh O(m^2) khi reuse_constant có hàng nghìn chữ ký
) -> RecoveryResult:
    """Khôi phục khóa riêng `d` từ MỘT danh sách chữ ký (có thể từ nhiều `r`
    khác nhau — hàm tự nhóm). Đây là API cấp cao, cài đúng pseudocode
    `recover_private_key` trong `signatures/nonce_theory.md` §7:

      1. Nhóm chữ ký theo `r` (ca biên 5.4: nhóm cỡ 1 bị bỏ qua — không rò gì).
      2. Trong mỗi nhóm, thử MỌI cặp (giới hạn `max_pairs_per_group` để tránh
         bùng nổ O(m²) với nhóm `reuse_constant` có thể có hàng nghìn chữ ký
         — xem nonce_theory.md §6: chỉ cần 1 cặp hợp lệ là đủ, cặp thêm chỉ
         tăng độ tin cậy chứ không "dễ hơn" về mặt toán học).
      3. Mỗi cặp: thử 4 tổ hợp dấu (ca biên 5.2), bỏ qua cặp suy biến
         `e_i==e_j` (ca biên 5.1).
      4. Nếu có `public_key`: CHỈ giữ ứng viên thoả `d·G==Q` (xác nhận bắt
         buộc). Nếu không: dùng đa số phiếu trên MỌI ứng viên tìm được.
      5. Trả về nhóm/ứng viên có nhiều phiếu nhất; nếu có nhiều nhóm `r` đều
         cho kết quả, lấy nhóm có `d` được xác nhận (hoặc nhiều phiếu nhất).

    `public_key`: NÊN truyền khi có (gần như luôn có trong thực tế — chứng
    thư/JWK công khai). Thiếu nó, kết quả dễ sai do ca biên 5.2/5.3 không có
    cách phân biệt chắc chắn (xem nonce_theory.md Mục 5.3 về nhóm r lẫn
    khóa) — hàm vẫn chạy được nhưng `verified_by_public_key=False`, cần
    diễn giải thận trọng hơn.
    """
    curve = get_curve(curve_input)
    groups = _group_by_r(signatures)
    if not groups:
        return RecoveryResult(
            success=False, groups_examined=0, pairs_examined=0,
            reason="Không tìm thấy nhóm nào có >=2 chữ ký cùng r trong dữ liệu đầu vào "
                   "(ca biên 5.4 — chưa có bằng chứng tái sử dụng nonce).",
        )

    best: Optional[RecoveryResult] = None
    total_pairs_examined = 0

    for r_hex, sigs in groups.items():
        sample = sigs[:max_pairs_per_group_to_sample_size(len(sigs), max_pairs_per_group)]
        votes: Counter = Counter()
        evidence_by_d: Dict[int, List[Tuple[Any, Any]]] = defaultdict(list)
        any_verified = False
        pairs_this_group = 0

        for sig_i, sig_j in itertools.combinations(sample, 2):
            pairs_this_group += 1
            e_i = hash_hex_to_e(curve, _field(sig_i, "msg_hash"))
            e_j = hash_hex_to_e(curve, _field(sig_j, "msg_hash"))
            s_i = int(_field(sig_i, "s"))
            s_j = int(_field(sig_j, "s"))
            r = int(r_hex)

            if public_key is not None:
                d = recover_d_from_pair(curve, e_i, r, s_i, e_j, s_j, public_key=public_key)
                if d is not None:
                    votes[d] += 1
                    evidence_by_d[d].append((sig_i, sig_j))
                    any_verified = True
            else:
                for d in candidate_ds_from_pair(curve, e_i, r, s_i, e_j, s_j):
                    votes[d] += 1
                    evidence_by_d[d].append((sig_i, sig_j))

        total_pairs_examined += pairs_this_group
        if not votes:
            continue

        d_best, n_votes = votes.most_common(1)[0]
        n = curve.n
        # k suy lại từ cặp bằng chứng đầu tiên (chỉ để báo cáo, không ảnh hưởng d_best)
        sig_a, sig_b = evidence_by_d[d_best][0]
        e_a = hash_hex_to_e(curve, _field(sig_a, "msg_hash"))
        e_b = hash_hex_to_e(curve, _field(sig_b, "msg_hash"))
        r_val = int(r_hex)
        s_a, s_b = int(_field(sig_a, "s")), int(_field(sig_b, "s"))
        k_candidates = [
            ((e_a - e_b) * _mod_inv(((s_a_sign - s_b_sign) % n), n)) % n
            for s_a_sign in (s_a % n, (-s_a) % n)
            for s_b_sign in (s_b % n, (-s_b) % n)
            if (s_a_sign - s_b_sign) % n != 0
        ]
        k_val = next(
            (kc for kc in k_candidates if scalar_mult(curve, kc, curve.G) is not None
             and (scalar_mult(curve, kc, curve.G)[0] % n) == r_val),
            k_candidates[0] if k_candidates else None,
        )

        candidate_result = RecoveryResult(
            success=True,
            d=d_best,
            k=k_val,
            r_group=r_hex,
            evidence_pairs=evidence_by_d[d_best],
            candidate_votes=dict(votes),
            verified_by_public_key=(public_key is not None and any_verified),
            groups_examined=1,
            pairs_examined=pairs_this_group,
            reason=(
                f"Khôi phục từ nhóm r={r_hex[:16]}... ({len(sigs)} chữ ký, "
                f"{pairs_this_group} cặp đã thử, {n_votes} cặp đồng thuận "
                f"{'và đã xác nhận d·G==Q' if public_key is not None else '(CHƯA xác nhận bằng public_key)'}."
            ),
        )

        if best is None or _is_better(candidate_result, best):
            best = candidate_result

    if best is None:
        return RecoveryResult(
            success=False, groups_examined=len(groups), pairs_examined=total_pairs_examined,
            reason="Có nhóm cùng r nhưng MỌI cặp đều suy biến (ca biên 5.1: e_i==e_j ở mọi "
                   "tổ hợp dấu) hoặc không cặp nào thoả d·G==Q khi đã có public_key "
                   "(có thể nhóm r bị lẫn khóa — ca biên 5.3).",
        )

    best.groups_examined = len(groups)
    best.pairs_examined = total_pairs_examined
    return best


def max_pairs_per_group_to_sample_size(group_size: int, max_pairs: int) -> int:
    """Chuyển giới hạn SỐ CẶP (max_pairs) thành giới hạn SỐ CHỮ KÝ lấy mẫu
    trong nhóm (vì số cặp = C(m,2)). Tìm m lớn nhất sao cho C(m,2) <= max_pairs,
    tối thiểu m=2 (luôn thử được ít nhất 1 cặp nếu nhóm có >=2 chữ ký)."""
    m = 2
    while m + 1 <= group_size and (m + 1) * m // 2 <= max_pairs:
        m += 1
    return max(m, min(2, group_size))


def _is_better(a: RecoveryResult, b: RecoveryResult) -> bool:
    """Ưu tiên: đã xác nhận bằng public_key > chưa; rồi tới số phiếu cao hơn."""
    a_key = (a.verified_by_public_key, a.candidate_votes.get(a.d, 0))
    b_key = (b.verified_by_public_key, b.candidate_votes.get(b.d, 0))
    return a_key > b_key


# ---------------------------------------------------------------------------
# 5. Self-test / demo (chạy: python -m signatures.nonce_reuse_attacker)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets
    from signatures.base_signer import BaseECDSASigner  # type: ignore
    from signatures.vulnerable_signer import make_vulnerable_signer  # type: ignore

    print("== 1) reuse_constant: 2 chữ ký, có public_key ==")
    d_true = secrets.randbelow(2 ** 256)
    signer = make_vulnerable_signer("reuse_constant", private_key=d_true, strategy_kwargs={"seed": 1})
    sigs = [signer.sign(b"payA"), signer.sign(b"payB")]
    res = recover_private_key(signer.curve, sigs, public_key=signer.public_key)
    print(" ", res.reason)
    assert res.success and res.d == d_true and res.verified_by_public_key

    print("\n== 2) reuse_constant, KHÔNG truyền public_key (chỉ đa số phiếu, 1 cặp) ==")
    res_nopk = recover_private_key(signer.curve, sigs)
    print(" ", res_nopk.reason)
    # Chỉ 1 cặp -> không có gì để "đa số phiếu" phân biệt 4 tổ hợp dấu; chấp
    # nhận có thể sai nếu không xác nhận thêm — đây CHÍNH LÀ lý do nên luôn
    # truyền public_key khi có.
    print("  (lưu ý: không có public_key, kết quả có thể là bất kỳ ứng viên nào trong "
          "4 tổ hợp dấu — xem candidate_votes):", res_nopk.candidate_votes)

    print("\n== 3) reuse_sparse (rho=0.6, 40 chữ ký, nhiều nhóm r) ==")
    d_true2 = secrets.randbelow(2 ** 256)
    signer2 = make_vulnerable_signer("reuse_sparse", private_key=d_true2,
                                      strategy_kwargs={"rho": 0.6, "seed": 42})
    msgs2 = [f"evt:{i}".encode() for i in range(40)]
    sigs2 = [signer2.sign(m) for m in msgs2]
    res2 = recover_private_key(signer2.curve, sigs2, public_key=signer2.public_key)
    print(" ", res2.reason)
    assert res2.success and res2.d == d_true2 and res2.verified_by_public_key

    print("\n== 4) Ca biên 5.1: toàn bộ nhóm r chỉ có chữ ký TRÙNG THÔNG ĐIỆP ==")
    sig_dup_a = signer.sign(b"same-msg")
    sig_dup_b = signer.sign(b"same-msg")  # cùng msg -> e giống hệt -> suy biến
    res3 = recover_private_key(signer.curve, [sig_dup_a, sig_dup_b], public_key=signer.public_key)
    print(" ", res3.reason)
    assert res3.success is False

    print("\n== 5) Ca biên 5.4: không có nhóm r nào trùng (toàn chữ ký độc lập) ==")
    signer_safe = make_vulnerable_signer("reuse_constant", private_key=secrets.randbelow(2**256),
                                          strategy_kwargs={"seed": 2})
    # chỉ 1 chữ ký -> không nhóm được
    res4 = recover_private_key(signer_safe.curve, [signer_safe.sign(b"solo")])
    print(" ", res4.reason)
    assert res4.success is False

    print("\n== 6) Ca biên 5.2 (low-S flip) qua D3-like dict thay vì SignatureResult ==")
    d_true3 = secrets.randbelow(2 ** 256)
    signer3 = make_vulnerable_signer("reuse_constant", private_key=d_true3, strategy_kwargs={"seed": 3})
    sA = signer3.sign(b"m1")
    sB = signer3.sign(b"m2")
    n3 = signer3.curve.n
    # Mô phỏng 1 thư viện đã chuẩn hoá low-S cho sB trước khi lưu vào "D3"
    s_b_lowS = min(int(sB.s), n3 - int(sB.s))
    d3_rows = [
        {"sig_id": "sig-a", "r": sA.r, "s": sA.s, "msg_hash": sA.msg_hash},
        {"sig_id": "sig-b", "r": sB.r, "s": str(s_b_lowS), "msg_hash": sB.msg_hash},
    ]
    res5 = recover_private_key(signer3.curve, d3_rows, public_key=signer3.public_key)
    print(" ", res5.reason)
    assert res5.success and res5.d == d_true3

    print("\nSelf-test hoàn tất: mọi assert pass (bao gồm cả 2 ca biên suy biến).")