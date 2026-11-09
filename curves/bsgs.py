"""
curves/bsgs.py
==============
Baby-Step Giant-Step (Shanks) cho ECDLP: cho G (bậc n) và Q = d*G, tìm d trong [1, n).

Đặt m = ceil(sqrt(n)), d = i*m + j với 0 <= j < m:
    d*G = Q  <=>  Q - i*m*G = j*G
    - Baby steps : lưu bảng {j*G -> j}, j = 0..m-1
    - Giant steps: với i = 0, 1, ..., tính Q - i*(m*G) rồi tra bảng
    - Thời gian  : O(sqrt(n)) phép cộng điểm
    - Bộ nhớ     : O(sqrt(n)) điểm

Số học đường cong dùng từ ECC.py (ECC, Point).
"""

import math
from ECC import ECC, Point


def bsgs(curve: ECC, G: Point, Q: Point, n: int, m: int = None) -> dict:
    """m: kích thước bảng baby-step; mặc định ceil(sqrt(n))."""
    if m is None:
        m = math.isqrt(n - 1) + 1 if n > 1 else 1       # ceil(sqrt(n))
    if m < 1:
        raise ValueError("m phải >= 1")

    result = {"d": None, "operations": 0, "memory_entries": 0,
              "restarts": None, "algo_params": {"m": m}}

    if Q.is_infinity:                                   # Q = O  =>  d ≡ 0 (mod n)
        result["d"] = 0
        return result

    ops = 0

    # Baby steps: table[j*G] = j (giữ j nhỏ nhất nếu trùng)
    table = {}
    R = Point(curve, is_infinity=True)                  # 0*G = O
    for j in range(m):
        table.setdefault(R, j)
        R = R + G
        ops += 1
    step = -R                                           # R = m*G  =>  step = -m*G
    result["memory_entries"] = len(table)

    # Giant steps: cur = Q - i*m*G
    cur = Q
    for i in range((n + m - 1) // m + 1):
        j = table.get(cur)
        if j is not None:
            result["d"] = (i * m + j) % n               # Q != O nên kết quả nằm trong [1, n)
            break
        cur = cur + step
        ops += 1

    result["operations"] = ops
    return result