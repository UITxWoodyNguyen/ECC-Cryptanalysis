from math import gcd
from random import randint
from curves.ecc import Point, FindOrder


def Pollard_Rho_ECC(A: Point, G: Point, max_retries: int = 16) -> int | None:
    if A.curve != G.curve:
        raise ValueError("A and G must be on the same curve")
    if A.is_infinity:
        return 0
    if G.is_infinity:
        return None

    n = FindOrder(G)
    if n == 1:
        return 0 if A.is_infinity else None

    def step_fn(state):
        X, k, l = state
        branch = 0 if X.is_infinity else int(X.x) % 3
        if branch == 0:
            return (X + A, k, (l + 1) % n)
        elif branch == 1:
            return (X + X, (2 * k) % n, (2 * l) % n)
        else:
            return (X + G, (k + 1) % n, l)

    for _ in range(max_retries):
        a = randint(1, max(1, n - 1))
        b = randint(1, max(1, n - 1))
        X0 = (a * G + b * A, a, b)
        tortoise = step_fn(X0)
        hare = step_fn(step_fn(X0))

        while tortoise[0] != hare[0]:
            tortoise = step_fn(tortoise)
            hare = step_fn(step_fn(hare))

        (_, k, l), (_, k_prime, l_prime) = tortoise, hare
        delta_l = (l_prime - l) % n
        delta_k = (k - k_prime) % n

        if delta_l == 0:
            continue

        g = gcd(delta_l, n)
        if delta_k % g != 0:
            continue

        m = n // g
        d = (delta_k // g) * pow(delta_l // g, -1, m) % m
        if g == 1:
            return d

        # Giải phần dư modulo g: target = t * step
        target = A - d * G
        step = m * G
        if g <= 1024:
            curr = Point(G.curve, is_infinity=True)
            for t in range(g):
                if curr == target:
                    return (d + m * t) % n
                curr = curr + step
            continue

        t = Pollard_Rho_ECC(target, step, max_retries)
        if t is not None:
            return (d + m * t) % n

    return None