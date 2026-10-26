from math import isqrt
import random
class ECC:
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, x: int, y: int) -> bool:
        return (y*y - (x*x*x + self.a * x + self.b)) % self.p == 0

    def __eq__(self, other):
        return (self.a, self.b, self.p) == (other.a, other.b, other.p)

    def __hash__(self):
        return hash((self.a, self.b, self.p))


class Point:
    def __init__(self, curve: ECC, x: int = None, y: int = None, is_infinity: bool = False):
        self.curve = curve
        self.x = x
        self.y = y
        self.is_infinity = is_infinity or (x is None and y is None)

    def __str__(self):
        return "Point(Infinity)" if self.is_infinity else f"Point({self.x}, {self.y})"

    def __neg__(self):
        if self.is_infinity: return self
        p = self.curve.p
        return Point(self.curve, self.x, (-self.y) % p)

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __hash__(self):
        if self.is_infinity:
            return hash((self.curve, None, None))
        return hash((self.curve, self.x, self.y))

    def __add__(self, other):
        if self.curve != other.curve:
            raise ValueError("Cannot add points from different curves")
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        p = self.curve.p
        if self.x == other.x and (self.y + other.y) % p == 0:
            return Point(self.curve, is_infinity=True)
        if self == other:
            slope = (3 * self.x * self.x + self.curve.a) * pow(2 * self.y, -1, p) % p
        else:
            slope = (other.y - self.y) * pow(other.x - self.x, -1, p) % p
        x3 = (slope * slope - self.x - other.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, n):
        if n < 0:
            return (-n) * (-self)
        if n == 0:
            return Point(self.curve, is_infinity=True)
        if n == 1:
            return self
        Q = self
        R = Point(self.curve, None, None)
        while n > 0:
            if n & 1: R = R + Q
            Q = Q + Q
            n >>= 1
        return R

    def __rmul__(self, n):
        return self.__mul__(n)


class MontgomeryECC:
    def __init__(self, A: int, B: int, p: int):
        self.A = A
        self.B = B
        self.p = p

    def is_on_curve(self, x: int, y: int) -> bool:
        return (self.B * y * y - (x*x*x + self.A * x*x + x)) % self.p == 0

    def __eq__(self, other):
        return (self.A, self.B, self.p) == (other.A, other.B, other.p)

    def __hash__(self):
        return hash((self.A, self.B, self.p))


class MontgomeryPoint:
    def __init__(self, curve: MontgomeryECC, x: int = None, y: int = None, is_infinity: bool = False):
        self.curve = curve
        self.x = x
        self.y = y
        self.is_infinity = is_infinity or (x is None and y is None)

    def __str__(self):
        return "Point(Infinity)" if self.is_infinity else f"Point({self.x}, {self.y})"

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __hash__(self):
        if self.is_infinity:
            return hash((self.curve, None, None))
        return hash((self.curve, self.x, self.y))

    def __neg__(self):
        if self.is_infinity: return self
        p = self.curve.p
        return MontgomeryPoint(self.curve, self.x, (-self.y) % p)

    def __add__(self, other):
        if self.curve != other.curve:
            raise ValueError("Cannot add points from different curves")
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        p = self.curve.p
        A = self.curve.A
        B = self.curve.B
        if self.x == other.x and (self.y + other.y) % p == 0:
            return MontgomeryPoint(self.curve, is_infinity=True)
        if self == other:
            num = (3 * self.x * self.x + 2 * A * self.x + 1) % p
            den = (2 * B * self.y) % p
            slope = (num * pow(den, -1, p)) % p
        else:
            num = (other.y - self.y) % p
            den = (other.x - self.x) % p
            slope = (num * pow(den, -1, p)) % p
        x3 = (B * slope * slope - A - self.x - other.x) % p
        y3 = (slope * (self.x - x3) - self.y) % p
        return MontgomeryPoint(self.curve, x3, y3)

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, n: int):
        if n < 0:
            return (-n) * (-self)
        if n == 0:
            return MontgomeryPoint(self.curve, is_infinity=True)
        if n == 1:
            return self
        R0, R1 = self, self + self
        for bit in bin(n)[3:]:
            if bit == '0':
                R1 = R0 + R1
                R0 = R0 + R0
            else:
                R0 = R0 + R1
                R1 = R1 + R1
        return R0

    def __rmul__(self, n: int):
        return self.__mul__(n)


#=======FUNCTIONS NumTheory============

def GCD(a, b):
    while b:
        a,b = b,a%b
    return a

def GCD_binary(a,b):
    a, b = abs(a), abs(b)
    if a == 0:
        return b
    if b == 0:
        return a
    g = 1
    while a%2 == 0 and b%2 == 0:
        a//=2
        b//=2
        g*=2
    while a != 0:
        while a%2 == 0: a//=2
        while b%2 == 0: b//=2
        if a >= b: a = (a-b)//2
        else: a, b = (b - a) // 2, a
    return g*b

def extended_euclid(a,b):
    s, old_s, t, old_t, r, old_r = 0, 1, 1, 0, b, a
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q*r
        old_s, s = s, old_s - q*s
        old_t, t = t, old_t - q*t
    d, x, y = old_r, old_s, old_t
    return d, x, y

def inv_mod(a,m):
    d, x, y = extended_euclid(a, m)
    if d != 1:
        return None
    return x % m

def CRT(rems, mods):
    # rems = [remainders], mods = [moduli] (pairwise coprime)
    M = 1
    for m in mods:
        M *= m
    x = 0
    for r, m in zip(rems, mods):
        Mi = M // m
        yi = inv_mod(Mi, m)
        if yi is None:
            raise ValueError("Moduli not coprime")
        x += r * Mi * yi
    return x % M

def Floyd_cycle(f, x0):
    tortoise = f(x0)
    hare = f(f(x0))
    while tortoise != hare:
        tortoise= f(tortoise)
        hare = f(f(hare))
    return tortoise, hare

def test_convergent(k: int, d: int, e: int, N: int) -> bool:
    if (e*d - 1) % k != 0:
        return False
    phi = (e*d - 1) // k
    s = N - phi + 1
    discriminant = s*s - 4*N
    if discriminant < 0: return False
    sqrt_d = isqrt(discriminant)
    if sqrt_d * sqrt_d != discriminant: return False
    if (s + sqrt_d) % 2 != 0:
        return False
    p = (s + sqrt_d) // 2
    q = (s - sqrt_d) // 2
    return p*q == N and p > 1 and q > 1

def _is_prime(n):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _pollard_rho(n):
    if n % 2 == 0:
        return 2
    while True:
        c = random.randrange(1, n)
        x = random.randrange(2, n)
        y, d = x, 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = GCD_binary(abs(x - y), n)
        if d != n:
            return d


def _factor(n):
    if n == 1:
        return {}
    if _is_prime(n):
        return {n: 1}
    d = _pollard_rho(n)
    factors = _factor(d)
    for q, e in _factor(n // d).items():
        factors[q] = factors.get(q, 0) + e
    return factors


def _order_multiple(P):
    """A positive multiple of ord(P), found inside the Hasse interval."""
    p = P.curve.p
    m = isqrt(2 * isqrt(p) + 2) + 1  # m^2 >= 2*sqrt(p) covers |trace| <= 2*sqrt(p)
    table = {}
    R = 0 * P
    for j in range(m):
        table.setdefault(R, j)
        R = R + P
    Q = (p + 1) * P
    step = m * P
    minus, plus = Q, Q
    for i in range(m + 1):
        for cur, t in ((minus, i * m), (plus, -i * m)):
            if cur in table:
                n = p + 1 - (t + table[cur])
                if n > 0:
                    return n
        minus = minus - step
        plus = plus + step
    raise RuntimeError("BSGS failed to find a multiple of the point order")


def FindOrder(P) -> int:
    if P.is_infinity:
        return 1
    n = _order_multiple(P)
    for q in _factor(n):
        while n % q == 0 and ((n // q) * P).is_infinity:
            n //= q
    return n


def factorint(n: int) -> dict[int, int]:
    """Return the prime factorisation of n as {prime: exponent}."""
    if n < 1:
        raise ValueError("factorint() requires a positive integer")

    factors = {}
    while n % 2 == 0:
        factors[2] = factors.get(2, 0) + 1
        n //= 2

    d = 3
    # shortcut: trial division is O(sqrt n); fine for curve orders up to 2^40.
    # Upgrade to Pollard rho (or sympy.factorint) for larger inputs.
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 2

    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors
