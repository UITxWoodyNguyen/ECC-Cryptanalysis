from math import isqrt
import random
from cryptography.hazmat.primitives.asymmetric import ec
from fastecdsa.curve import P192, P224, P256, P384, P521, secp256k1

# 1. Map tham số từ fastecdsa sang (object OpenSSL, bậc nhóm q)
_OPENSSL_CURVES: dict[tuple[int, int, int], tuple[ec.EllipticCurve, int | None]] = {
    (c.a % c.p, c.b % c.p, c.p): (openssl_c, c.q)
    for c, openssl_c in [
        (P224, ec.SECP224R1()),
        (P256, ec.SECP256R1()),
        (P384, ec.SECP384R1()),
        (P521, ec.SECP521R1()),
        (secp256k1, ec.SECP256K1()),
    ]
}


def register_openssl_curve(
    a: int, b: int, p: int, openssl_curve: ec.EllipticCurve, order: int | None = None
):
    """Đăng ký thêm curve mới (kèm bậc nhóm order nếu biết để FindOrder chạy tức thì)."""
    _OPENSSL_CURVES[(a % p, b % p, p)] = (openssl_curve, order)


class ECC:
    def __init__(self, a: int, b: int, p: int):
        self.a = a % p
        self.b = b % p
        self.p = p
        entry = _OPENSSL_CURVES.get((self.a, self.b, self.p))
        self._openssl_curve = entry[0] if entry else None
        self._group_order = entry[1] if entry else None
        self._cached_g = None  # Cache tọa độ điểm sinh G

    @property
    def uses_openssl(self) -> bool:
        return self._openssl_curve is not None

    def get_standard_generator(self) -> tuple[int, int] | None:
        """Lấy tọa độ điểm sinh G chuẩn từ OpenSSL (có cache)."""
        if not self.uses_openssl:
            return None
        if self._cached_g is None:
            g_nums = ec.derive_private_key(1, self._openssl_curve).public_key().public_numbers()
            self._cached_g = (g_nums.x, g_nums.y)
        return self._cached_g

    def is_on_curve(self, x: int, y: int) -> bool:
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def __eq__(self, other):
        if not isinstance(other, ECC):
            return False
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
        if self.is_infinity:
            return self
        return Point(self.curve, self.x, (-self.y) % self.curve.p)

    def __eq__(self, other):
        if not isinstance(other, Point) or self.curve != other.curve:
            return False
        if self.is_infinity and other.is_infinity:
            return True
        return self.x == other.x and self.y == other.y

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

    def __mul__(self, n: int):
        if n < 0:
            return (-n) * (-self)
        if n == 0 or self.is_infinity:
            return Point(self.curve, is_infinity=True)
        if n == 1:
            return self

        # Nếu là điểm sinh G của curve chuẩn -> dùng OpenSSL tính n * G
        if self.curve.uses_openssl and (self.x, self.y) == self.curve.get_standard_generator():
            return self._mul_openssl_generator(n)

        # Fallback về Python thuần cho các điểm P != G hoặc curve tùy chỉnh
        Q = self
        R = Point(self.curve, is_infinity=True)
        while n > 0:
            if n & 1:
                R = R + Q
            Q = Q + Q
            n >>= 1
        return R

    def __rmul__(self, n: int):
        return self.__mul__(n)

    def _mul_openssl_generator(self, n: int) -> "Point":
        """Tính n * G trực tiếp bằng OpenSSL C backend."""
        q = self.curve._group_order
        if q is not None:
            n = n % q
            if n == 0:
                return Point(self.curve, is_infinity=True)
        try:
            priv = ec.derive_private_key(n, self.curve._openssl_curve)
            nums = priv.public_key().public_numbers()
            return Point(self.curve, nums.x, nums.y)
        except ValueError:
            # Trường hợp curve đăng ký thêm mà chưa truyền order và n >= q
            return Point(self.curve, is_infinity=True)


# ======= FUNCTIONS NumTheory & FindOrder ============

def _gcd_binary(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    if a == 0:
        return b
    if b == 0:
        return a
    g = 1
    while a % 2 == 0 and b % 2 == 0:
        a //= 2
        b //= 2
        g *= 2
    while a != 0:
        while a % 2 == 0:
            a //= 2
        while b % 2 == 0:
            b //= 2
        if a >= b:
            a = (a - b) // 2
        else:
            a, b = (b - a) // 2, a
    return g * b


def _is_prime(n: int) -> bool:
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


def _pollard_rho(n: int) -> int:
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
            d = _gcd_binary(abs(x - y), n)
        if d != n:
            return d


def _factor(n: int) -> dict[int, int]:
    if n == 1:
        return {}
    if _is_prime(n):
        return {n: 1}
    d = _pollard_rho(n)
    factors = _factor(d)
    for q, e in _factor(n // d).items():
        factors[q] = factors.get(q, 0) + e
    return factors


def _order_multiple(P: Point) -> int:
    """Tìm một bội số dương của ord(P) trong khoảng Hasse bằng BSGS."""
    p = P.curve.p
    m = isqrt(2 * isqrt(p) + 2) + 1
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

def CRT(remainder: list, moduli: list)-> int:
    if (len(remainder) != len(moduli)): 
        raise ValueError("Both list must be the same size")
    if not moduli:
        raise ValueError("Input lists cannot be empty")
    list_i = []
    BigModuli = 1
    for i in moduli:
        BigModuli *= i
    for i in range(len(moduli)):
        Ni = BigModuli//moduli[i]
        Mi = pow(Ni, -1, moduli[i])
        xi = Ni*Mi*remainder[i]
        list_i.append(xi)
    return sum(list_i) % BigModuli
    

def FindOrder(P: Point) -> int:
    """Tìm bậc chính xác của điểm P (dùng bậc nhóm q nếu là curve chuẩn, ngược lại dùng BSGS)."""
    if P.is_infinity:
        return 1

    # Nhánh 1: Đường cong chuẩn đã biết sẵn bậc nhóm q (NIST/SECG)
    if getattr(P.curve, "_group_order", None) is not None:
        n = P.curve._group_order
    # Nhánh 2: Đường cong tùy chỉnh nhỏ -> dùng BSGS
    else:
        n = _order_multiple(P)

    for q in _factor(n):
        while n % q == 0 and ((n // q) * P).is_infinity:
            n //= q
    return n

def _brent_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    while True:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = 128  # Gom 128 bước mới tính GCD 1 lần
        g, r, q = 1, 1, 1

        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n

            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = (q * abs(x - y)) % n
                g = _gcd_binary(q, n)
                k += m
            r *= 2

        if g == n:
            # Lùi lại từng bước nếu batch bị gộp quá lố
            while True:
                ys = (ys * ys + c) % n
                g = _gcd_binary(abs(x - ys), n)
                if g > 1:
                    break

        if g != n:
            return g


def factorint(n: int, trial_limit: int = 100_000) -> dict[int, int]:
    """
    Trial Division (Wheel 2,3,5) -> Miller-Rabin -> Brent Pollard's Rho.
    """
    if n < 1:
        raise ValueError("factorint() requires a positive integer")
    if n == 1:
        return {}

    factors: dict[int, int] = {}

    # 1. Tầng 1: Quét nhanh các thừa số nhỏ (2, 3, 5 và wheel mod 30)
    for p in (2, 3, 5):
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p

    # Bước nhảy wheel mod 30 bỏ qua các bội của 2, 3, 5 (tiết kiệm 73% phép chia)
    wheel = (4, 2, 4, 2, 4, 6, 2, 6)
    d = 7
    idx = 0
    limit = min(trial_limit, isqrt(n))
    while d <= limit:
        if n % d == 0:
            cnt = 0
            while n % d == 0:
                cnt += 1
                n //= d
            factors[d] = factors.get(d, 0) + cnt
            limit = min(trial_limit, isqrt(n))
        d += wheel[idx]
        idx = (idx + 1) & 7

    if n == 1:
        return factors

    # 2. Tầng 2 & 3: Đệ quy tách phần còn lại bằng Miller-Rabin + Brent Rho
    stack = [n]
    while stack:
        curr = stack.pop()
        if curr == 1:
            continue
        if _is_prime(curr):
            factors[curr] = factors.get(curr, 0) + 1
        else:
            divisor = _brent_rho(curr)
            stack.append(divisor)
            stack.append(curr // divisor)

    # Sắp xếp dict theo khóa nguyên tố tăng dần (rất hữu ích khi debug Pohlig-Hellman)
    return dict(sorted(factors.items()))