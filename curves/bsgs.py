from math import isqrt
from curves.ecc import Point, FindOrder


def BSGS_ECC(A: Point, G: Point) -> int | None:
    if A.curve != G.curve:
        raise ValueError("A and G must be on the same curve")
    if A.is_infinity:
        return 0
    if G.is_infinity:
        return None

    n = FindOrder(G)
    m = isqrt(n) + 1

    table = {}
    baby = Point(G.curve, is_infinity=True)
    for j in range(m):
        table.setdefault(baby, j)
        baby = baby + G

    # Giant-step
    giant_stride = m * G
    curr = A
    for i in range(m):
        if curr in table:
            return (i * m + table[curr]) % n
        curr = curr - giant_stride

    return None
