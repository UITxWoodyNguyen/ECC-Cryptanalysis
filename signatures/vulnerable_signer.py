"""
signatures/vulnerable_signer.py
=================================

**ECDSA Lab Signer cố định nonce k (CÓ CHỦ ĐÍCH).**

Cài đặt 4 "failure mode" sinh nonce `k` lỗi, mô phỏng các nguyên nhân THỰC TẾ
từng khiến khóa ECDSA bị lộ (Sony PlayStation 3 2010, SecureRandom Android
2013 — xem `signatures/nonce_theory.md` §9). Mỗi failure mode là 1 lớp con
của `NonceStrategy` (`signatures/base_signer.py`) — bản thân `BaseECDSASigner`
KHÔNG đổi, chỉ cắm chiến lược sinh `k` khác nhau (strategy pattern), đúng
kiến trúc đã thiết kế ở Tuần 2.

Khớp enum `NonceClass`/`SignerVersion` trong `data/schema_definition.json`:

    mode (NonceStrategy.name) | signer_version              | Mô phỏng
    --------------------------|------------------------------|---------------------------------
    reuse_constant            | vulnerable_constant           | F1: k hằng số cho MỌI chữ ký
    reuse_restart             | vulnerable_restart_seed       | F2: k lặp lại theo "đợt khởi động"
    reuse_sparse              | vulnerable_sparse_reuse       | F3: xác suất ρ tái dùng k cũ
    low_entropy               | vulnerable_low_entropy        | F4: k rút từ không gian rất nhỏ

CẢNH BÁO: Chỉ dùng trong `data/D3_signatures.csv` (corpus lab) và
`system-demos/jwt-es256/app.py` (dịch vụ demo CÓ CHỦ Ý dễ tổn thương). Không
bao giờ dùng các NonceStrategy này ngoài phạm vi nghiên cứu.

Trạng thái: DRAFT v0.1 — Tuần 5 (16/11-22/11), owner: Thành viên B.
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
from typing import Dict, List, Optional, Tuple, Type

# --- Import khung dùng chung từ signatures/base_signer.py -----------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from signatures.base_signer import (  # type: ignore
        NonceStrategy, BaseECDSASigner, CurveParams, get_curve, new_lab_key_id,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "vulnerable_signer.py cần signatures/base_signer.py cùng project-root. "
        f"Lỗi gốc: {exc}"
    ) from exc

__all__ = [
    "ReuseConstantNonceStrategy",
    "ReuseRestartNonceStrategy",
    "ReuseSparseNonceStrategy",
    "LowEntropyNonceStrategy",
    "MODE_REGISTRY",
    "make_vulnerable_signer",
]


def _rng(seed: Optional[int]) -> random.Random:
    """RNG tái lập được nếu có seed (bắt buộc cho thí nghiệm có thể chạy lại),
    ngược lại dùng nguồn ngẫu nhiên hệ thống."""
    return random.Random(seed) if seed is not None else random.SystemRandom()


# ---------------------------------------------------------------------------
# F1 — reuse_constant: k CỐ ĐỊNH cho mọi chữ ký
# ---------------------------------------------------------------------------

class ReuseConstantNonceStrategy(NonceStrategy):
    """F1: k CỐ ĐỊNH, dùng lại cho MỌI chữ ký của signer này — mô phỏng lỗi
    kiểu Sony PS3 (2010): firmware hard-code 1 giá trị "random" duy nhất.

    Chỉ cần đúng 2 chữ ký bất kỳ (khác thông điệp) của khóa này là đủ để
    khôi phục d (xem signatures/nonce_theory.md Mục 3)."""
    name = "reuse_constant"

    def __init__(self, *, k: Optional[int] = None, seed: Optional[int] = None) -> None:
        self._fixed_k = k          # nếu attacker/test muốn áp đặt k cụ thể
        self._seed = seed          # dùng khi phải tự sinh k lần đầu (lazy init)
        self._k: Optional[int] = k

    def generate(self, *, curve: "CurveParams", private_key: int, msg_hash_int: int) -> int:
        if self._k is None:
            # Lazy init: sinh k đúng 1 LẦN DUY NHẤT ở lần ký đầu tiên, rồi
            # dùng mãi mãi cho mọi lần ký sau — đúng bản chất lỗi F1.
            self._k = 1 + _rng(self._seed).randrange(curve.n - 1)
        return self._k

    @property
    def k_value(self) -> Optional[int]:
        """Giá trị k đang dùng — chỉ để debug/self-test, KHÔNG dùng trong corpus thật."""
        return self._k


# ---------------------------------------------------------------------------
# F2 — reuse_restart: k lặp lại theo "đợt khởi động" (seed hẹp)
# ---------------------------------------------------------------------------

class ReuseRestartNonceStrategy(NonceStrategy):
    """F2: mỗi lần "khởi động lại" dịch vụ, k được dẫn xuất TẤT ĐỊNH từ một
    seed rút ra từ không gian RẤT HẸP (vd boot counter, timestamp làm tròn
    giây, PID...). Trong cùng 1 đợt khởi động, k không đổi (giống F1 nhưng
    chỉ trong phạm vi đợt đó). Giữa các đợt khác nhau, do seed_space nhỏ,
    xác suất 2 đợt trùng seed (và do đó trùng k) KHÔNG nhỏ (hiệu ứng ngày
    sinh nhật: ~50% va chạm sau O(sqrt(2^seed_space_bits)) đợt).

    Gọi `restart()` để mô phỏng một lần khởi động lại mới."""
    name = "reuse_restart"

    def __init__(self, *, curve: "CurveParams", seed_space_bits: int = 8,
                 seed: Optional[int] = None) -> None:
        if seed_space_bits < 1:
            raise ValueError("seed_space_bits phải >= 1")
        self.curve = curve
        self.seed_space_bits = seed_space_bits
        self._rng = _rng(seed)
        self._epoch_seed: Optional[int] = None
        self._epoch_count = 0
        self.restart()  # khởi tạo đợt đầu tiên ngay khi tạo signer

    def restart(self) -> int:
        """Mô phỏng 1 lần khởi động lại: rút epoch_seed mới từ không gian hẹp
        [0, 2^seed_space_bits). Trả về epoch_seed (để test/log)."""
        self._epoch_seed = self._rng.randrange(1 << self.seed_space_bits)
        self._epoch_count += 1
        return self._epoch_seed

    def _derive_k(self) -> int:
        # Dẫn xuất k TẤT ĐỊNH từ epoch_seed qua SHA-256 rồi rút gọn về [1, n-1].
        # Việc băm chỉ để trải seed ra toàn miền n một cách tất định — bản
        # thân LỖI nằm ở chỗ epoch_seed chỉ có 2^seed_space_bits khả năng.
        digest = hashlib.sha256(
            f"restart-nonce:{self._epoch_seed}".encode()
        ).digest()
        raw = int.from_bytes(digest, "big")
        return 1 + (raw % (self.curve.n - 1))

    def generate(self, *, curve: "CurveParams", private_key: int, msg_hash_int: int) -> int:
        return self._derive_k()

    @property
    def epoch_seed(self) -> Optional[int]:
        return self._epoch_seed

    @property
    def epoch_count(self) -> int:
        return self._epoch_count


# ---------------------------------------------------------------------------
# F3 — reuse_sparse: xác suất ρ tái dùng 1 k đã từng dùng
# ---------------------------------------------------------------------------

class ReuseSparseNonceStrategy(NonceStrategy):
    """F3: mỗi lần ký, với xác suất `rho` lấy lại 1 k NGẪU NHIÊN đã dùng
    trước đó (từ pool), ngược lại sinh k mới hoàn toàn ngẫu nhiên và thêm
    vào pool. Mô phỏng rò rỉ/race-condition hiếm gặp trong bộ đệm entropy
    (gần với kiểu lỗi SecureRandom trên Android, 2013).

    Kỳ vọng số chữ ký cần quan sát tới lần trùng `r` đầu tiên ~ hình học
    theo `rho` (xem docs/experimental_design.md HC2) — không tất định như
    F1/F2, nên cần `seed` để tái lập kết quả giữa các lần chạy."""
    name = "reuse_sparse"

    def __init__(self, *, rho: float, seed: Optional[int] = None,
                 max_pool_size: Optional[int] = None) -> None:
        if not (0.0 <= rho <= 1.0):
            raise ValueError("rho phải trong [0, 1]")
        self.rho = rho
        self.max_pool_size = max_pool_size
        self._rng = _rng(seed)
        self._pool: List[int] = []

    def generate(self, *, curve: "CurveParams", private_key: int, msg_hash_int: int) -> int:
        if self._pool and self._rng.random() < self.rho:
            return self._rng.choice(self._pool)
        k = 1 + self._rng.randrange(curve.n - 1)
        if self.max_pool_size is None or len(self._pool) < self.max_pool_size:
            self._pool.append(k)
        return k

    @property
    def pool_size(self) -> int:
        return len(self._pool)


# ---------------------------------------------------------------------------
# F4 — low_entropy: k rút từ không gian RẤT NHỎ
# ---------------------------------------------------------------------------

class LowEntropyNonceStrategy(NonceStrategy):
    """F4: k được rút ĐỘC LẬP mỗi lần ký, nhưng từ không gian chỉ
    `2^entropy_bits` giá trị (thay vì toàn miền `[1, n-1]`). Hệ quả kép:
      (a) k có thể bị LIỆT KÊ trực tiếp (tầng L4 trong docs/threat_model.md —
          không cần cặp chữ ký trùng r, chỉ cần thử mọi k ứng viên); và
      (b) với entropy_bits đủ nhỏ, hiệu ứng ngày sinh nhật vẫn khiến 2 chữ ký
          tình cờ trùng k (trùng r) sau khoảng O(2^(entropy_bits/2)) chữ ký,
          mở lại đường tấn công ở signatures/nonce_theory.md.
    """
    name = "low_entropy"

    def __init__(self, *, entropy_bits: int, seed: Optional[int] = None) -> None:
        if entropy_bits < 1:
            raise ValueError("entropy_bits phải >= 1")
        self.entropy_bits = entropy_bits
        self._rng = _rng(seed)

    def generate(self, *, curve: "CurveParams", private_key: int, msg_hash_int: int) -> int:
        space = 1 << self.entropy_bits
        # k lấy TRỰC TIẾP trong [1, space] — KHÔNG băm trải ra toàn miền n,
        # vì chính không gian nhỏ (liệt kê được) mới là bản chất lỗi F4,
        # khác với F2 (không gian seed nhỏ nhưng k trải đều nhờ hash).
        upper = max(space - 1, 1)
        return 1 + self._rng.randrange(upper)


# ---------------------------------------------------------------------------
# Factory — dựng signer dễ tổn thương theo tên mode
# ---------------------------------------------------------------------------

# mode (NonceStrategy.name) -> (signer_version khớp schema, class NonceStrategy)
MODE_REGISTRY: Dict[str, Tuple[str, Type[NonceStrategy]]] = {
    "reuse_constant": ("vulnerable_constant", ReuseConstantNonceStrategy),
    "reuse_restart": ("vulnerable_restart_seed", ReuseRestartNonceStrategy),
    "reuse_sparse": ("vulnerable_sparse_reuse", ReuseSparseNonceStrategy),
    "low_entropy": ("vulnerable_low_entropy", LowEntropyNonceStrategy),
}


def make_vulnerable_signer(
    mode: str,
    *,
    curve="P-256",
    private_key: int,
    key_id: Optional[str] = None,
    strategy_kwargs: Optional[dict] = None,
) -> BaseECDSASigner:
    """Dựng 1 BaseECDSASigner dễ tổn thương theo `mode` ∈ MODE_REGISTRY.

    `strategy_kwargs` truyền thẳng vào constructor của NonceStrategy tương ứng
    (vd {"rho": 0.1, "seed": 1} cho 'reuse_sparse', {"seed_space_bits": 8}
    cho 'reuse_restart', {"entropy_bits": 20} cho 'low_entropy').

    `key_id` nếu không truyền sẽ tự sinh với tiền tố LAB- (guardrail an toàn
    đã ép buộc ở BaseECDSASigner.__init__)."""
    if mode not in MODE_REGISTRY:
        raise ValueError(f"mode={mode!r} không hợp lệ; chọn 1 trong {sorted(MODE_REGISTRY)}")
    signer_version, strategy_cls = MODE_REGISTRY[mode]
    kwargs = dict(strategy_kwargs or {})

    curve_obj = get_curve(curve)
    if strategy_cls is ReuseRestartNonceStrategy:
        kwargs.setdefault("curve", curve_obj)  # F2 bắt buộc cần curve lúc khởi tạo

    strategy = strategy_cls(**kwargs)
    if key_id is None:
        key_id = new_lab_key_id(mode)

    return BaseECDSASigner(
        curve=curve_obj,
        private_key=private_key,
        key_id=key_id,
        signer_version=signer_version,
        nonce_strategy=strategy,
    )


# ---------------------------------------------------------------------------
# Self-test / demo (chạy: python -m signatures.vulnerable_signer)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets as _secrets

    def _repeated_r_groups(sigs) -> Dict[str, List[int]]:
        groups: Dict[str, List[int]] = {}
        for idx, s in enumerate(sigs):
            groups.setdefault(s.r, []).append(idx)
        return {r: idxs for r, idxs in groups.items() if len(idxs) > 1}

    d = _secrets.randbelow(2 ** 256)
    messages = [f"order:id={i}".encode() for i in range(12)]

    print("== F1 reuse_constant ==")
    s1 = make_vulnerable_signer("reuse_constant", private_key=d, strategy_kwargs={"seed": 1})
    sigs1 = [s1.sign(m) for m in messages[:4]]
    ok_all = all(
        BaseECDSASigner.verify(s1.curve, s1.public_key, m, int(sig.r), int(sig.s))
        for m, sig in zip(messages[:4], sigs1)
    )
    rs = {sig.r for sig in sigs1}
    print(f"  4 chữ ký, verify() hợp lệ hết: {ok_all}; số r KHÁC NHAU: {len(rs)} (kỳ vọng 1)")
    assert ok_all and len(rs) == 1

    print("\n== F2 reuse_restart (seed_space_bits=2 -> 4 khả năng, 5 đợt restart) ==")
    s2 = make_vulnerable_signer("reuse_restart", private_key=d,
                                 strategy_kwargs={"seed_space_bits": 2, "seed": 7})
    strat2 = s2.nonce_strategy
    sigs2 = []
    for epoch in range(5):  # 5 đợt > 4 khả năng -> chắc chắn có đợt trùng (chim bồ câu)
        if epoch > 0:
            strat2.restart()
        sigs2.append(s2.sign(messages[epoch]))
    rs2 = [sig.r for sig in sigs2]
    dup2 = _repeated_r_groups(sigs2)
    ok2 = all(
        BaseECDSASigner.verify(s2.curve, s2.public_key, messages[i], int(sig.r), int(sig.s))
        for i, sig in enumerate(sigs2)
    )
    print(f"  r qua 5 đợt: {[r[:10]+'...' for r in rs2]}")
    print(f"  verify() hợp lệ hết: {ok2}; số nhóm r trùng giữa các đợt: {len(dup2)}")
    assert ok2 and len(dup2) >= 1, "Với 5 đợt > 4 khả năng seed, PHẢI có ít nhất 1 cặp trùng (pigeonhole)"

    print("\n== F3 reuse_sparse (rho=0.6, 40 chữ ký) ==")
    s3 = make_vulnerable_signer("reuse_sparse", private_key=d,
                                 strategy_kwargs={"rho": 0.6, "seed": 42})
    msgs3 = [f"evt:{i}".encode() for i in range(40)]
    sigs3 = [s3.sign(m) for m in msgs3]
    dup3 = _repeated_r_groups(sigs3)
    ok3 = all(
        BaseECDSASigner.verify(s3.curve, s3.public_key, m, int(sig.r), int(sig.s))
        for m, sig in zip(msgs3, sigs3)
    )
    total_in_dup_groups = sum(len(v) for v in dup3.values())
    print(f"  verify() hợp lệ hết: {ok3}; pool_size cuối: {s3.nonce_strategy.pool_size}; "
          f"số nhóm r trùng: {len(dup3)} (gộp {total_in_dup_groups}/{len(sigs3)} chữ ký)")
    assert ok3 and len(dup3) >= 1, "rho=0.6 trên 40 chữ ký gần như chắc chắn có reuse"

    print("\n== F4 low_entropy (entropy_bits=10 -> không gian k chỉ 1024 giá trị) ==")
    s4 = make_vulnerable_signer("low_entropy", private_key=d,
                                 strategy_kwargs={"entropy_bits": 10, "seed": 99})
    msgs4 = [f"tx:{i}".encode() for i in range(80)]
    sigs4 = [s4.sign(m) for m in msgs4]
    dup4 = _repeated_r_groups(sigs4)
    ok4 = all(
        BaseECDSASigner.verify(s4.curve, s4.public_key, m, int(sig.r), int(sig.s))
        for m, sig in zip(msgs4, sigs4)
    )
    print(f"  verify() hợp lệ hết: {ok4}; số nhóm r trùng trên 80 chữ ký "
          f"(kỳ vọng cao vì không gian k chỉ 2^10=1024): {len(dup4)}")
    assert ok4
    # Với không gian 1024 và 80 mẫu, theo xấp xỉ ngày sinh nhật xác suất va chạm rất cao -> nên có >=1 nhóm trùng
    print(f"  (lưu ý: ngay cả khi KHÔNG trùng r, k vẫn chỉ nằm trong {1<<10:,} khả năng -> "
          f"liệt kê trực tiếp để kiểm tra r = x(kG) mod n là khả thi, đây là ý nghĩa chính của F4)")

    print("\nSelf-test hoàn tất: cả 4 failure mode đều sinh chữ ký HỢP LỆ về mặt "
          "mật mã (verify() pass) nhưng rò rỉ nonce theo đúng cơ chế mô tả.")