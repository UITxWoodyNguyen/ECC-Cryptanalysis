from curves.ecc import *
from math import *
def BSGS_ECC(A: Point, G: Point) -> int:
    n = FindOrder(G)
    m = ceil(sqrt(n))
    table = {}
    for j in range(m):
        table[j * G] = j
    R = m * G
    curr = A
    for i in range(m):
        if curr in table:
            return (i * m + table[curr]) % n
        curr = curr - R
    return None
