"""
curves/pollard_rho.py
=====================
Pollard's Rho cho ECDLP (memoryless, Floyd): cho G (bậc n) và Q = d*G, tìm d trong [1, n).

    - Random walk trên X_i = a_i*G + b_i*Q (theo dõi a_i, b_i mod n song song).
    - r-adding walk: chia điểm thành L lớp theo x mod L, mỗi lớp cộng một điểm cố định
      M_s = alpha_s*G + beta_s*Q.
    - Floyd: rùa 1 bước, thỏ 2 bước đến khi X_rùa == X_thỏ:
          a1*G + b1*Q = a2*G + b2*Q   =>   (a1 - a2) = d*(b2 - b1)  (mod n)
    - gcd(b2 - b1, n) = g > 1: thử g nghiệm ứng viên, kiểm lại d*G == Q;
      va chạm "xấu" (b2 == b1, ...) thì khởi động lại với điểm xuất phát mới.
    - Thời gian: kỳ vọng O(sqrt(n)) phép cộng điểm; Bộ nhớ: O(1).

Dùng từ curves/ecc.py: ECC, Point, GCD_binary, inv_mod, FindOrder.
`operations` chỉ đếm phép cộng điểm của các walk.
"""

import math
import random
from curves.ecc import ECC, Point, GCD_binary, inv_mod, FindOrder


def _solve_collision(G: Point, Q: Point, n: int, a1: int, b1: int, a2: int, b2: int):
    """Giải (a1 - a2) = d*(b2 - b1) mod n; trả về d thoả d*G == Q hoặc None."""
    da = (a1 - a2) % n
    db = (b2 - b1) % n
    if db == 0:                                         # va chạm tầm thường
        return None
    g = GCD_binary(db, n)
    if da % g != 0:
        return None
    n_g = n // g
    d0 = (da // g) * inv_mod(db // g, n_g) % n_g if n_g > 1 else 0
    for t in range(g):                                  # g nghiệm ứng viên mod n
        d = d0 + t * n_g
        if d != 0 and d * G == Q:
            return d
    return None


def pollard_rho(curve: ECC, G: Point, Q: Point, n: int, partitions: int = 20,
                rng_seed: int = None, max_restarts: int = 1000,
                max_steps_factor: float = 30.0) -> dict:
    """
    partitions       : số lớp L của r-adding walk.
    rng_seed         : seed cho bảng bước đi / điểm xuất phát (mặc định suy ra từ Q).
    max_restarts     : giới hạn số lần khởi động lại.
    max_steps_factor : mỗi walk dừng sau max_steps_factor*sqrt(n)+100 bước rồi restart.
    """
    result = {"d": None, "operations": 0, "memory_entries": None, "restarts": 0,
              "algo_params": {"partitions": partitions, "num_walks": 1}}

    if Q.is_infinity:                                   # Q = O  =>  d ≡ 0 (mod n)
        result["d"] = 0
        return result
    if n < 2:
        return result

    if rng_seed is None:
        rng_seed = (Q.x * 1000003 ^ Q.y) & 0xFFFFFFFF
    rng = random.Random(rng_seed)
    ops = 0

    # Bảng bước đi hằng số: M_s = alpha_s*G + beta_s*Q
    L = max(2, partitions)
    steps = []
    for _ in range(L):
        al, be = rng.randrange(1, n), rng.randrange(1, n)
        steps.append((al, be, al * G + be * Q))

    def advance(X, a, b):
        s = steps[X.x % L] if not X.is_infinity else steps[0]
        return X + s[2], (a + s[0]) % n, (b + s[1]) % n

    max_steps = int(max_steps_factor * math.isqrt(n)) + 100

    for restart in range(max_restarts + 1):
        result["restarts"] = restart
        result["algo_params"]["num_walks"] = restart + 1
        a0, b0 = rng.randrange(n), rng.randrange(n)
        X0 = a0 * G + b0 * Q
        tx, ta, tb = X0, a0, b0                         # rùa
        hx, ha, hb = X0, a0, b0                         # thỏ

        for _ in range(max_steps):
            tx, ta, tb = advance(tx, ta, tb)
            hx, ha, hb = advance(hx, ha, hb)
            hx, ha, hb = advance(hx, ha, hb)
            ops += 3
            if tx == hx:
                d = _solve_collision(G, Q, n, ta, tb, ha, hb)
                if d is not None:
                    result.update(d=d, operations=ops)
                    return result
                break                             # va chạm "xấu" -> restart

    result["operations"] = ops
    return result


def Pollard_Rho_ECC(A: Point, G: Point, max_retries: int = 10) -> int:
    """Wrapper tương thích API cũ: trả về d sao cho A = d*G."""
    n = FindOrder(G)
    return pollard_rho(G.curve, G, A, n, max_restarts=max_retries)["d"]