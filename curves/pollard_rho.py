from curves.ecc import *
from math import gcd
from random import randint
def Pollard_Rho_ECC(A: Point, G: Point, max_retries: int = 10) -> int:
    n = FindOrder(G)
    def f(state):
        X, k, l = state
        subnet = 0 if X.is_infinity else int(X.x) % 3
        if subnet == 0:
            return (X + A, k, (l + 1) % n)
        elif subnet == 1:
            return (X + X, (2 * k) % n, (2 * l) % n)
        else:
            return (X + G, (k + 1) % n, l)
    for _ in range(max_retries):
        a, b = randint(1, n - 1), randint(1, n - 1)
        X0 = (a * G + b * A, a, b)
        tortoise, hare = f(X0), f(f(X0))
        while tortoise[0] != hare[0]:
            tortoise, hare = f(tortoise), f(f(hare))
        (X, k, l), (X_prime, k_prime, l_prime) = tortoise, hare
        delta_l = (l_prime - l) % n
        delta_k = (k - k_prime) % n
        if delta_l == 0:
            continue
        # d*delta_l == delta_k (mod n); solve mod n/g, then recurse on the g part
        g = gcd(delta_l, n)
        m = n // g
        d = (delta_k // g) * pow(delta_l // g, -1, m) % m
        if g == 1:
            return d
        target = A - d * G
        step = m * G
        # shortcut: brute-force the remaining g <= 1024; recurse above that
        if g <= 1024:
            for t in range(g):
                if target == t * step:
                    return (d + m * t) % n
            continue
        t = Pollard_Rho_ECC(target, step, max_retries)
        if t is not None:
            return (d + m * t) % n
    return None
