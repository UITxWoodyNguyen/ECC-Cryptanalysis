"""
signatures/repeated_r_detector.py
====================================

**Repeated-r Detector** — phát hiện chữ ký ECDSA trùng `r` trong một luồng
(stream), độ phức tạp `O(1)` amortized mỗi lần thêm, `O(N)` tổng thể trên
`N` chữ ký quan sát được (tra bảng băm `r -> [chữ ký]`, không phải vét cạn
từng cặp).

Đây là bản triển khai "thật" mà `signatures/nonce_reuse_attacker.py` đã dự
trù sẵn chỗ để thay thế bộ gom nhóm nội bộ tối giản của nó (`_group_by_r`) —
xem phần tích hợp ở cuối file đó. Vì sao tách riêng module này thay vì để
luôn trong `nonce_reuse_attacker.py`:

    - Phát hiện trùng `r` và khôi phục `d` là 2 việc khác nhau: một hệ thống
      giám sát (monitoring) có thể chỉ cần CẢNH BÁO khi phát hiện trùng `r`
      (vd ghi log, chặn key, gửi alert) mà không cần (hoặc không có quyền)
      chạy thuật toán khôi phục khóa.
    - Cho phép đo `sigs_to_first_repeat` và P/R của chính bộ phát hiện một
      cách độc lập với thuật toán khôi phục (đúng tiêu chí chấp nhận ở
      `docs/experimental_design.md` C.2: "detector precision=recall=1.0").

Trạng thái: DRAFT v0.1 — Tuần 6, owner: Thành viên B.
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Hashable, Iterable, List, Optional, Sequence, Tuple, Union

# --- Import tiện ích đọc field dùng chung với nonce_reuse_attacker.py -----
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

SignatureLike = Union[Any, Dict[str, Any]]  # SignatureResult hoặc dict khớp D3


def _field(sig: SignatureLike, name: str) -> Any:
    """Đọc thuộc tính dù `sig` là dataclass (SignatureResult) hay dict (bản
    ghi D3). Trùng logic với signatures/nonce_reuse_attacker.py để 2 module
    luôn hiểu cùng 1 kiểu dữ liệu đầu vào như nhau."""
    if isinstance(sig, dict):
        return sig[name]
    return getattr(sig, name)


def _field_or_none(sig: SignatureLike, name: str) -> Any:
    if isinstance(sig, dict):
        return sig.get(name)
    return getattr(sig, name, None)


__all__ = [
    "RepeatedRDetector",
    "detect_repeated_r",
    "DetectionMetrics",
    "evaluate_against_ground_truth",
]


# ---------------------------------------------------------------------------
# 1. Detector — dùng cho luồng (stream), thêm dần từng chữ ký
# ---------------------------------------------------------------------------

class RepeatedRDetector:
    """Tra bảng băm `r` (hoặc `(key_id, r)`) → danh sách chữ ký, O(1) mỗi
    lần `add()`. Dùng được cho cả batch (đưa hết 1 list vào `add_many`) lẫn
    streaming thật (gọi `add()` mỗi khi có 1 chữ ký mới tới).

    `group_by_key`:
        - `False` (mặc định, khớp hành vi `nonce_reuse_attacker._group_by_r`
          cũ để tích hợp không đổi kết quả): chỉ nhóm theo `r`. Phù hợp khi
          **đã biết** luồng chỉ gồm chữ ký của 1 khóa (vd giám sát 1 service
          ký duy nhất), hoặc khi cố ý muốn phát hiện cả trùng `r` GIỮA các
          khóa khác nhau (kiểu sự cố Android SecureRandom — nhiều khóa khác
          nhau chia sẻ cùng nguồn entropy lỗi).
        - `True`: nhóm theo `(key_id, r)` — dùng khi luồng trộn chữ ký của
          NHIỀU khóa và chỉ muốn báo động khi CÙNG 1 khóa tự lặp lại `r` của
          chính nó (loại trừ khả năng 2 khóa khác nhau tình cờ trùng `r`,
          xem ca biên 5.3 trong `signatures/nonce_theory.md`).
    """

    def __init__(self, *, group_by_key: bool = False) -> None:
        self.group_by_key = group_by_key
        self._index: Dict[Hashable, List[SignatureLike]] = defaultdict(list)
        self._n_seen: int = 0
        self._first_repeat_index: Optional[int] = None  # 1-based, theo thu tu them vao

    def _key(self, sig: SignatureLike) -> Hashable:
        r = str(_field(sig, "r"))
        if self.group_by_key:
            return (str(_field(sig, "key_id")), r)
        return r

    def add(self, sig: SignatureLike) -> bool:
        """Thêm 1 chữ ký. Trả về `True` nếu chữ ký này vừa khiến 1 nhóm đạt
        kích thước >= 2 lần đầu tiên (tức là chữ ký "tố giác" sự trùng lặp)."""
        self._n_seen += 1
        key = self._key(sig)
        group = self._index[key]
        is_new_collision = (len(group) == 1)
        group.append(sig)
        if is_new_collision and self._first_repeat_index is None:
            self._first_repeat_index = self._n_seen
        return is_new_collision

    def add_many(self, sigs: Iterable[SignatureLike]) -> "RepeatedRDetector":
        for s in sigs:
            self.add(s)
        return self

    def repeated_groups(self, min_size: int = 2) -> Dict[Hashable, List[SignatureLike]]:
        """Mọi nhóm (theo `r` hoặc `(key_id,r)`) có >= `min_size` chữ ký."""
        return {k: v for k, v in self._index.items() if len(v) >= min_size}

    def flagged_signatures(self) -> List[SignatureLike]:
        """Danh sách phẳng mọi chữ ký thuộc 1 nhóm >=2 — đây là tập
        "repeated_r=True theo detector", dùng để so với ground truth."""
        out: List[SignatureLike] = []
        for sigs in self._index.values():
            if len(sigs) >= 2:
                out.extend(sigs)
        return out

    @property
    def n_seen(self) -> int:
        return self._n_seen

    @property
    def n_groups_total(self) -> int:
        return len(self._index)

    @property
    def n_groups_repeated(self) -> int:
        return sum(1 for v in self._index.values() if len(v) >= 2)

    def sigs_to_first_repeat(self) -> Optional[int]:
        """Số chữ ký đã quan sát tính đến (và bao gồm) chữ ký đầu tiên gây
        ra va chạm — None nếu chưa từng có va chạm. Khớp định nghĩa
        `sigs_to_first_repeat` trong docs/experimental_design.md C.8."""
        return self._first_repeat_index

    def reset(self) -> None:
        self._index.clear()
        self._n_seen = 0
        self._first_repeat_index = None


def detect_repeated_r(
    signatures: Sequence[SignatureLike], *, group_by_key: bool = False
) -> RepeatedRDetector:
    """Tiện ích batch: chạy detector trên 1 danh sách chữ ký có sẵn, trả về
    detector đã nạp đầy đủ (để gọi tiếp `.repeated_groups()`,
    `.flagged_signatures()`, `.sigs_to_first_repeat()`...)."""
    return RepeatedRDetector(group_by_key=group_by_key).add_many(signatures)


# ---------------------------------------------------------------------------
# 2. Đánh giá so với ground truth (tiêu chí chấp nhận: precision=recall=1.0)
# ---------------------------------------------------------------------------

@dataclass
class DetectionMetrics:
    precision: float
    recall: float
    f1: float
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "precision": self.precision, "recall": self.recall, "f1": self.f1,
            "true_positive": self.true_positive, "false_positive": self.false_positive,
            "false_negative": self.false_negative, "true_negative": self.true_negative,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return (f"DetectionMetrics(precision={self.precision:.3f}, recall={self.recall:.3f}, "
                f"f1={self.f1:.3f}, TP={self.true_positive}, FP={self.false_positive}, "
                f"FN={self.false_negative}, TN={self.true_negative})")


def evaluate_against_ground_truth(
    records: Sequence[SignatureLike], *, group_by_key: bool = False
) -> DetectionMetrics:
    """So khớp nhãn dự đoán của detector với nhãn ground truth sẵn có trong
    dữ liệu (trường `repeated_r`, đúng cột trong `data/D3_signatures.csv`).

    Mỗi bản ghi PHẢI có `sig_id` (để đối chiếu) và `repeated_r` (ground
    truth, bool). Dùng được trực tiếp với các dòng đọc từ D3.
    """
    detector = detect_repeated_r(records, group_by_key=group_by_key)
    flagged_ids = {str(_field(s, "sig_id")) for s in detector.flagged_signatures()}

    tp = fp = fn = tn = 0
    for r in records:
        predicted = str(_field(r, "sig_id")) in flagged_ids
        truth = bool(_field_or_none(r, "repeated_r"))
        if predicted and truth:
            tp += 1
        elif predicted and not truth:
            fp += 1
        elif not predicted and truth:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return DetectionMetrics(precision, recall, f1, tp, fp, fn, tn)


# ---------------------------------------------------------------------------
# 3. Self-test / demo (chạy: python -m signatures.repeated_r_detector)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import csv
    import secrets

    from signatures.vulnerable_signer import make_vulnerable_signer  # type: ignore
    from signatures.base_signer import RandomNonceStrategy, BaseECDSASigner, new_lab_key_id  # type: ignore

    print("== 1) Streaming cơ bản: reuse_constant, kỳ vọng va chạm ở chữ ký thứ 2 ==")
    d_true = secrets.randbelow(2 ** 256)
    signer = make_vulnerable_signer("reuse_constant", private_key=d_true, strategy_kwargs={"k": 7})
    det = RepeatedRDetector()
    flags = []
    for i in range(5):
        sig = signer.sign(f"m{i}".encode())
        flags.append(det.add(sig))
    print("  Cờ 'va chạm mới' theo từng chữ ký (1..5):", flags)
    print("  sigs_to_first_repeat:", det.sigs_to_first_repeat())
    print("  n_groups_repeated:", det.n_groups_repeated, "/ n_groups_total:", det.n_groups_total)
    assert flags == [False, True, False, False, False]
    assert det.sigs_to_first_repeat() == 2

    print("\n== 2) Negative control: random_ok, kỳ vọng KHÔNG có va chạm trên 200 chữ ký ==")
    signer_safe = BaseECDSASigner(
        curve="P-256", private_key=secrets.randbelow(2 ** 256),
        key_id=new_lab_key_id("safe"), signer_version="random_ok",
        nonce_strategy=RandomNonceStrategy(),
    )
    det_safe = detect_repeated_r([signer_safe.sign(f"x{i}".encode()) for i in range(200)])
    print("  n_groups_repeated:", det_safe.n_groups_repeated, "(kỳ vọng 0)")
    assert det_safe.n_groups_repeated == 0

    print("\n== 3) group_by_key=True: tách đúng dù 2 khóa khác nhau tình cờ 'đụng' r ==")
    d_A, d_B = secrets.randbelow(2 ** 256), secrets.randbelow(2 ** 256)
    signerA = make_vulnerable_signer("reuse_constant", private_key=d_A,
                                      key_id=new_lab_key_id("ka"), strategy_kwargs={"k": 4})
    signerB = make_vulnerable_signer("reuse_constant", private_key=d_B,
                                      key_id=new_lab_key_id("kb"), strategy_kwargs={"k": 4})
    sigA1, sigA2 = signerA.sign(b"a1"), signerA.sign(b"a2")
    sigB1 = {"sig_id": "forced", "key_id": signerA.key_id,  # ép key_id GIỐNG A để mô phỏng "lẫn nhóm"
             "r": signerB.sign(b"b1").r, "s": "0"}
    det_mixed_strict = detect_repeated_r([sigA1, sigA2, sigB1], group_by_key=True)
    det_mixed_loose = detect_repeated_r([sigA1, sigA2, sigB1], group_by_key=False)
    print("  group_by_key=True -> nhóm repeated:", det_mixed_strict.n_groups_repeated,
          "(kỳ vọng 1: đúng cặp sigA1/sigA2 cùng key_id A, r khác sigB1)")
    print("  group_by_key=False -> nếu r sigB1 trùng ngẫu nhiên vẫn gộp theo r thô")
    assert det_mixed_strict.n_groups_repeated == 1

    print("\n== 4) Đánh giá trên corpus thật data/D3_signatures.csv (nếu có) ==")
    d3_path = os.path.join(_PROJECT_ROOT, "data", "D3_signatures.csv")
    if os.path.exists(d3_path):
        with open(d3_path, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            row["repeated_r"] = (row["repeated_r"] == "True")
        metrics = evaluate_against_ground_truth(rows, group_by_key=True)
        print("  ", metrics)
        print(f"  precision={metrics.precision:.3f}, recall={metrics.recall:.3f} "
              f"(tiêu chí chấp nhận: cả 2 = 1.0)")
        assert metrics.precision == 1.0 and metrics.recall == 1.0
    else:
        print("  Bỏ qua — không tìm thấy data/D3_signatures.csv trong môi trường này.")

    print("\nSelf-test hoàn tất: mọi assert pass.")