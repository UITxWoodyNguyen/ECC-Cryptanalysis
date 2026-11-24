from math import isqrt
from curves.ecc import Point, FindOrder, factorint, CRT


def _build_baby_table(base: Point, order: int) -> tuple[dict[Point, int], Point, int]:
    m = isqrt(order) + 1
    table = {}
    baby = Point(base.curve, is_infinity=True)
    for j in range(m):
        table.setdefault(baby, j)
        baby = baby + base
    giant_stride = m * base
    return table, giant_stride, m


def _bsgs_with_table(
    target: Point, order: int, table: dict[Point, int], giant_stride: Point, m: int
) -> int | None:
    if target.is_infinity:
        return 0
    curr = target
    for i in range(m):
        if curr in table:
            return (i * m + table[curr]) % order
        curr = curr - giant_stride
    return None


def solve_subgroup(P: Point, Q: Point, p: int, e: int, n: int) -> int | None:
    P_base = (n // p) * P
    table, giant_stride, m = _build_baby_table(P_base, p)

    k_sub = 0
    p_pow = 1       # p^j
    p_next = p      # p^(j + 1)
    curr_Q = Q      # Q - k_sub * P

    for _ in range(e):
        H = (n // p_next) * curr_Q
        z = _bsgs_with_table(H, p, table, giant_stride, m)
        if z is None:
            return None

        k_sub += z * p_pow
        if z != 0:
            curr_Q = curr_Q - (z * p_pow) * P

        p_pow = p_next
        p_next *= p

    return k_sub


def pohlig_hellman_ecc(Q: Point, P: Point) -> int | None:
    if P.curve != Q.curve:
        raise ValueError("Q and P must be on the same curve")
    if Q.is_infinity:
        return 0
    if P.is_infinity:
        return None

    n = FindOrder(P)
    factors = factorint(n)

    remainders = []
    moduli = []
    for prime, exp in factors.items():
        k_i = solve_subgroup(P, Q, prime, exp, n)
        if k_i is None:
            return None
        remainders.append(k_i)
        moduli.append(prime ** exp)

    return CRT(remainders, moduli) % n