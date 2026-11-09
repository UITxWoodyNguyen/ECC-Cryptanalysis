"""
curves/exhaustive_search.py
===========================
Exhaustive Scalar Search cho ECDLP: cho G (bậc n) và Q = d*G, tìm d.

Thuật toán: thử k = 1, 2, ..., n-1 với R_k = R_{k-1} + G cho đến khi R_k == Q.
    - Thời gian: O(n) phép cộng điểm
    - Bộ nhớ   : O(1)

Số học đường cong dùng từ curves/ecc.py (ECC, Point).
`operations` chỉ đếm phép cộng điểm trong vòng lặp chính.
"""

from curves.ecc import ECC, Point


def exhaustive_scalar_search(curve: ECC, G: Point, Q: Point, n: int) -> dict:
    result = {"d": None, "operations": 0, "memory_entries": None,
              "restarts": None, "algo_params": {}}

    if Q.is_infinity:                   # Q = O  =>  d ≡ 0 (mod n)
        result["d"] = 0
        return result

    R = G
    ops = 0
    for k in range(1, n):
        if R == Q:
            result["d"] = k
            break
        R = R + G
        ops += 1
    result["operations"] = ops
    return result


def Exhaustive_search(P: Point, Q: Point, Bounds: int) -> int:
    """Wrapper tương thích API cũ: tìm n nhỏ nhất (1 <= n < Bounds) sao cho P == n*Q."""
    n = 1
    while n < Bounds:
        if P == n * Q:
            return n
        n += 1
    return None