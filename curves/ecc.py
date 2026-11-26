from math import isqrt
import random
from cryptography.hazmat.primitives.asymmetric import ec
try:
    from fastecdsa.curve import P192, P224, P256, P384, P521, secp256k1

    # 1. Map tham số từ fastecdsa sang (object OpenSSL, bậc nhóm q)
    _CANDIDATE_CURVES = [
        (P192, getattr(ec, "SECP192R1", None)),
        (P224, getattr(ec, "SECP224R1", None)),
        (P256, getattr(ec, "SECP256R1", None)),
        (P384, getattr(ec, "SECP384R1", None)),
        (P521, getattr(ec, "SECP521R1", None)),
        (secp256k1, getattr(ec, "SECP256K1", None)),
    ]

    _OPENSSL_CURVES: dict[tuple[int, int, int], tuple[ec.EllipticCurve, int | None]] = {
        (c.a % c.p, c.b % c.p, c.p): (openssl_cls(), c.q)
        for c, openssl_cls in _CANDIDATE_CURVES
        if openssl_cls is not None
    }
except ImportError:
    _OPENSSL_CURVES = {}


def register_openssl_curve(
    a: int, b: int, p: int, openssl_curve: ec.EllipticCurve, order: int | None = None
):
    """Đăng ký thêm curve mới (kèm bậc nhóm order nếu biết để FindOrder chạy tức thì)."""
    _OPENSSL_CURVES[(a % p, b % p, p)] = (openssl_curve, order)


# ======= NUMBER THEORY HELPERS (Public cho toàn dự án) ============

_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    """Kiểm tra nguyên tố bằng Miller-Rabin tất định (chính xác tới n < 3.3e24)."""
    if n < 2:
        return False
    for q in _MR_BASES:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _MR_BASES:
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


def random_prime(rng: random.Random, bits: int) -> int:
    """Số nguyên tố ngẫu nhiên có đúng `bits` bit."""
    if bits < 8:
        raise ValueError("bits phải >= 8 cho toy curve")
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(cand):
            return cand

def sqrt_mod(n: int, p: int) -> int | None:
    """Tính căn bậc hai modulo p nguyên tố lẻ bằng Tonelli-Shanks; trả về None nếu không tồn tại."""
    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t, r = t * c % p, r * b % p
    return r


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
            while True:
                ys = (ys * ys + c) % n
                g = _gcd_binary(abs(x - ys), n)
                if g > 1:
                    break

        if g != n:
            return g


def factorint(n: int, trial_limit: int = 100_000) -> dict[int, int]:
    """
    Phân tích thừa số nguyên tố của n:
    Trial Division (Wheel 2,3,5) -> Miller-Rabin -> Brent Pollard's Rho.
    """
    if n < 1:
        raise ValueError("factorint() requires a positive integer")
    if n == 1:
        return {}

    factors: dict[int, int] = {}

    for p in (2, 3, 5):
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p

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

    stack = [n]
    while stack:
        curr = stack.pop()
        if curr == 1:
            continue
        if is_prime(curr):
            factors[curr] = factors.get(curr, 0) + 1
        else:
            divisor = _brent_rho(curr)
            stack.append(divisor)
            stack.append(curr // divisor)

    return dict(sorted(factors.items()))


# Alias tương thích với các module khác (pohlig_hellman, gen_smooth_curves...)
factorize = factorint


def CRT(remainder: list[int], moduli: list[int]) -> int:
    """Giải hệ đồng dư tuyến tính bằng Định lý Thặng dư Trung Hoa (CRT)."""
    if len(remainder) != len(moduli):
        raise ValueError("Both lists must be the same size")
    if not moduli:
        raise ValueError("Input lists cannot be empty")
    big_moduli = 1
    for m in moduli:
        big_moduli *= m
    total = 0
    for r, m in zip(remainder, moduli):
        ni = big_moduli // m
        mi = pow(ni, -1, m)
        total += ni * mi * r
    return total % big_moduli


# ======= ELLIPTIC CURVE & POINT CLASSES ============

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

    def discriminant(self) -> int:
        return (4 * pow(self.a, 3, self.p) + 27 * self.b * self.b) % self.p

    def is_nonsingular(self) -> bool:
        return self.discriminant() != 0

    def rhs(self, x: int) -> int:
        return (x * x * x + self.a * x + self.b) % self.p

    def is_on_curve(self, x: int, y: int) -> bool:
        return (y * y - self.rhs(x)) % self.p == 0

    def get_standard_generator(self) -> tuple[int, int] | None:
        """Lấy tọa độ điểm sinh G chuẩn từ OpenSSL (có cache)."""
        if not self.uses_openssl:
            return None
        if self._cached_g is None:
            g_nums = ec.derive_private_key(1, self._openssl_curve).public_key().public_numbers()
            self._cached_g = (g_nums.x, g_nums.y)
        return self._cached_g

    def random_point(self, rng: random.Random | None = None) -> "Point":
        """Chọn một điểm affine ngẫu nhiên trên đường cong."""
        rng = rng or random
        while True:
            x = rng.randrange(self.p)
            y = sqrt_mod(self.rhs(x), self.p)
            if y is not None:
                y_val = y if rng.getrandbits(1) else (-y) % self.p
                return Point(self, x, y_val)

    def find_generator(self, min_order_ratio: float = 0.25) -> "Point":
        """Tìm điểm sinh G có bậc đủ lớn trên đường cong (dùng Tonelli-Shanks)."""
        if self.uses_openssl:
            gx, gy = self.get_standard_generator()
            return Point(self, gx, gy)
        for x in range(1, min(self.p, 2000)):
            y = sqrt_mod(self.rhs(x), self.p)
            if y is not None:
                pt = Point(self, x, y)
                if FindOrder(pt) > max(10, int(self.p * min_order_ratio)):
                    return pt
        raise RuntimeError(f"Cannot find generator mod {self.p}")

    def __eq__(self, other):
        if not isinstance(other, ECC):
            return False
        return (self.a, self.b, self.p) == (other.a, other.b, other.p)

    def __hash__(self):
        return hash((self.a, self.b, self.p))


class Point:
    def __init__(self, curve: ECC, x: int | None = None, y: int | None = None, is_infinity: bool = False):
        self.curve = curve
        self.x = x
        self.y = y
        self.is_infinity = is_infinity or (x is None and y is None)

    def __str__(self):
        return "Point(Infinity)" if self.is_infinity else f"Point({self.x}, {self.y})"

    def __repr__(self):
        return self.__str__()

    def __neg__(self):
        if self.is_infinity:
            return self
        return Point(self.curve, self.x, (-self.y) % self.curve.p)

    def __eq__(self, other):
        if not isinstance(other, Point) or self.curve != other.curve:
            return False
        if self.is_infinity or other.is_infinity:
            return self.is_infinity and other.is_infinity
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
            if self.y % p == 0:
                return Point(self.curve, is_infinity=True)
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

    def to_jacobian(self) -> "JacobianPoint":
        """Chuyển đổi điểm Affine sang tọa độ Jacobian (X:Y:Z) với Z=1 (hoặc Z=0 nếu vô cực)."""
        return JacobianPoint.from_affine(self)

    def montgomery_ladder(self, n: int) -> "Point":
        """
        Nhân vô hướng bằng Montgomery ladder (constant-operation pattern).
        Mẫu thao tác cố định theo bit-length, giảm timing leakage (Section III.4 math_notes.md).
        """
        if n < 0:
            return (-self).montgomery_ladder(-n)
        if n == 0 or self.is_infinity:
            return Point(self.curve, is_infinity=True)
        R0 = Point(self.curve, is_infinity=True)
        R1 = self
        for i in range(n.bit_length() - 1, -1, -1):
            if (n >> i) & 1:
                R0 = R0 + R1
                R1 = R1 + R1
            else:
                R1 = R0 + R1
                R0 = R0 + R0
        return R0

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
            return Point(self.curve, is_infinity=True)


class JacobianPoint:
    """
    Điểm trên đường cong Weierstrass trong tọa độ Jacobian (X:Y:Z) (Section II math_notes.md).
    Biểu diễn điểm Affine (x, y) với x = X / Z^2, y = Y / Z^3 (Z != 0).
    Điểm vô cực O được biểu diễn với Z = 0 (thường dùng 1:1:0).
    Loại bỏ phép nghịch đảo modulo trong các bước cộng/nhân đôi trung gian.
    """
    def __init__(self, curve: ECC, X: int, Y: int, Z: int):
        self.curve = curve
        self.X = X % curve.p
        self.Y = Y % curve.p
        self.Z = Z % curve.p
        self.is_infinity = (self.Z == 0)

    @classmethod
    def from_affine(cls, P: Point) -> "JacobianPoint":
        """Chuyển điểm Affine sang Jacobian: (x, y) -> (x, y, 1), O -> (1, 1, 0)."""
        if P.is_infinity:
            return cls(P.curve, 1, 1, 0)
        return cls(P.curve, P.x, P.y, 1)

    def to_affine(self) -> Point:
        """Chuyển điểm Jacobian về Affine: chỉ tốn 1 phép nghịch đảo duy nhất mod p."""
        if self.is_infinity or self.Z == 0:
            return Point(self.curve, is_infinity=True)
        p = self.curve.p
        z_inv = pow(self.Z, -1, p)
        z_inv2 = (z_inv * z_inv) % p
        z_inv3 = (z_inv2 * z_inv) % p
        x = (self.X * z_inv2) % p
        y = (self.Y * z_inv3) % p
        return Point(self.curve, x, y)

    def __neg__(self) -> "JacobianPoint":
        if self.is_infinity:
            return self
        return JacobianPoint(self.curve, self.X, (-self.Y) % self.curve.p, self.Z)

    def double(self) -> "JacobianPoint":
        """Nhân đôi điểm 2P trong tọa độ Jacobian theo công thức Section II.1 math_notes.md."""
        if self.is_infinity or self.Y == 0:
            return JacobianPoint(self.curve, 1, 1, 0)
        p = self.curve.p
        X1, Y1, Z1 = self.X, self.Y, self.Z
        Y1_sq = (Y1 * Y1) % p
        S = (4 * X1 * Y1_sq) % p
        Z1_4 = pow(Z1, 4, p)
        M = (3 * X1 * X1 + self.curve.a * Z1_4) % p
        X3 = (M * M - 2 * S) % p
        Y1_4 = (Y1_sq * Y1_sq) % p
        Y3 = (M * (S - X3) - 8 * Y1_4) % p
        Z3 = (2 * Y1 * Z1) % p
        return JacobianPoint(self.curve, X3, Y3, Z3)

    def __add__(self, other: "JacobianPoint") -> "JacobianPoint":
        """Cộng hai điểm P1 + P2 trong tọa độ Jacobian theo công thức Section II.2 math_notes.md."""
        if self.curve != other.curve:
            raise ValueError("Cannot add points from different curves")
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        p = self.curve.p
        Z1_sq = (self.Z * self.Z) % p
        Z2_sq = (other.Z * other.Z) % p
        U1 = (self.X * Z2_sq) % p
        U2 = (other.X * Z1_sq) % p
        S1 = (self.Y * Z2_sq * other.Z) % p
        S2 = (other.Y * Z1_sq * self.Z) % p
        H = (U2 - U1) % p
        R = (S2 - S1) % p
        if H == 0:
            if R == 0:
                return self.double()
            return JacobianPoint(self.curve, 1, 1, 0)
        H_sq = (H * H) % p
        H_cu = (H_sq * H) % p
        U1_H2 = (U1 * H_sq) % p
        X3 = (R * R - H_cu - 2 * U1_H2) % p
        Y3 = (R * (U1_H2 - X3) - S1 * H_cu) % p
        Z3 = (H * self.Z * other.Z) % p
        return JacobianPoint(self.curve, X3, Y3, Z3)

    def __sub__(self, other: "JacobianPoint") -> "JacobianPoint":
        return self + (-other)

    def __mul__(self, n: int) -> "JacobianPoint":
        if n < 0:
            return (-self) * (-n)
        if n == 0 or self.is_infinity:
            return JacobianPoint(self.curve, 1, 1, 0)
        R = JacobianPoint(self.curve, 1, 1, 0)
        Q = self
        while n > 0:
            if n & 1:
                R = R + Q
            Q = Q.double()
            n >>= 1
        return R

    def __rmul__(self, n: int) -> "JacobianPoint":
        return self.__mul__(n)

    def __repr__(self) -> str:
        return f"JacobianPoint(Infinity)" if self.is_infinity else f"JacobianPoint({self.X}, {self.Y}, {self.Z})"


# ======= PUBLIC KEY VALIDATION & DOMAIN CRITERIA ============

def validate_public_key(P: Point, order: int | None = None) -> tuple[bool, str]:
    """
    Quy trình validation điểm công khai theo Section VI.2 math_notes.md & SP 800-56A:
    1. Kiểm tra điểm vô cực (P != O)
    2. Kiểm tra miền tọa độ (0 <= x, y < p)
    3. Kiểm tra on-curve (y^2 == x^3 + ax + b mod p)
    4. Kiểm tra subgroup membership ([n]P == O) nếu biết bậc nhóm con order n
    """
    if P.is_infinity:
        return False, "Point at infinity"
    p = P.curve.p
    if not (0 <= P.x < p and 0 <= P.y < p):
        return False, "Coordinates out of range [0, p-1]"
    if not P.curve.is_on_curve(P.x, P.y):
        return False, "Point is not on the curve (invalid curve)"
    if order is not None:
        if not (order * P).is_infinity:
            return False, f"Point does not belong to prime subgroup of order {order}"
    return True, "Valid"


def cofactor_clearing(P: Point, h: int) -> Point:
    """Thực hiện cofactor clearing: P* = [h]P theo SP 800-56A để triệt tiêu thành phần subgroup nhỏ."""
    return h * P


def embedding_degree(n: int, p: int, max_k: int = 100) -> int | None:
    """
    Tính embedding degree k nhỏ nhất sao cho n | (p^k - 1), tức p^k == 1 (mod n).
    Dùng để phát hiện đường cong yếu trước tấn công MOV/Frey-Rück (Section V.7 math_notes.md).
    Trả về None nếu không tìm thấy k <= max_k.
    """
    if n <= 1 or p % n == 0:
        return None
    p_mod = p % n
    val = p_mod
    for k in range(1, max_k + 1):
        if val == 1:
            return k
        val = (val * p_mod) % n
    return None


# ======= ORDER COMPUTATION ============

def _order_multiple(P: Point) -> int:
    """Tìm một bội số dương của ord(P) trong khoảng Hasse bằng BSGS."""
    p = P.curve.p
    m = isqrt(2 * isqrt(p) + 2) + 1
    table = {}
    R = Point(P.curve, is_infinity=True)
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


def FindOrder(P: Point, group_order_hint: int | None = None) -> int:
    """
    Tìm bậc chính xác của điểm P:
    - Nếu truyền group_order_hint (ví dụ #E đã biết), bỏ qua BSGS và chia dần trực tiếp.
    - Nếu là đường cong chuẩn NIST/SECG, lấy sẵn bậc nhóm q.
    - Ngược lại dùng BSGS trên khoảng Hasse.
    """
    if P.is_infinity:
        return 1

    if group_order_hint is not None:
        n = group_order_hint
    elif getattr(P.curve, "_group_order", None) is not None:
        n = P.curve._group_order
    else:
        n = _order_multiple(P)

    for q in factorint(n):
        while n % q == 0 and ((n // q) * P).is_infinity:
            n //= q
    return n