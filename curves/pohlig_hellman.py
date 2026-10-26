from curves.ecc import *
from curves.bsgs import BSGS_ECC

def SolveSubGroup(P: Point, Q: Point, p: int, e: int, n: int):
    P_base = (n // p) * P
    k_sub = 0
    for j in range(e):
        scaled = Q - k_sub * P
        H = (n // (p ** (j + 1))) * scaled
        z = BSGS_ECC(H, P_base)
        if z is None:
            return None
        k_sub += z * (p ** j)
    return k_sub


def Pohlig_hellman_ECC(Q: Point, P: Point) -> int:
    n = FindOrder(P)
    factors = factorint(n)
    remainders = []
    moduli = []
    for prime, exp in factors.items():
        modulus = prime ** exp
        k_i = SolveSubGroup(P, Q, prime, exp, n)
        if k_i is None:
            return None
        remainders.append(k_i)
        moduli.append(modulus)
    k = CRT(remainders, moduli)
    return k % n

