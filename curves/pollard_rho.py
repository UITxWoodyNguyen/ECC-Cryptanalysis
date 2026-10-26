from curves.ECC import *
from random import randint
def Pollard_Rho_ECC(A: Point, G: Point, max_retries: int = 5) -> int:
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
        if GCD_binary(delta_l, n) == 1:
            return (delta_k * pow(delta_l, -1, n)) % n
    return None
