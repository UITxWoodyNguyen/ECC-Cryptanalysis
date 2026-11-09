"""
curves/toy_curve_gen.py -- Module sinh đường cong Elliptic "toy" trên F_p
=========================================================================
Topic 14: ECC Cryptanalysis -- Track A (generic ECDLP search).

Sinh các đường cong Weierstrass ngắn  E: y^2 = x^3 + a*x + b  (mod p)
với p nguyên tố cỡ 16..48 bit, đếm số điểm #E(F_p), phân tích thừa số,
chọn điểm cơ sở G và xuất bản ghi đúng chuẩn D1 (data/schema_definition.json).

Các chế độ sinh (--modes / tham số `mode`):
  prime     h = 1, n = #E nguyên tố          -> category "safe_prime_order"
  cofactor  #E = h*n, n nguyên tố, 2<=h<=H   -> category "cofactor_gt1"
  smooth    #E có mọi ước nguyên tố <= B     -> category "smooth_order"
            (dùng cho Pohlig-Hellman; gen_smooth_curves.py có thể tái dùng)

Đếm điểm: p < 2^16 dùng đếm trực tiếp; còn lại dùng BSGS trên khoảng Hasse
(kiểu Mestre), độ phức tạp ~ O(p^(1/4)) -- đủ nhanh tới p ~ 48 bit trong Python.

Hạn chế (cố ý, vì đây là toy): Miller-Rabin tất định chỉ đúng tới ~3.3e24;
không dùng cho tham số mật mã thật.

Cách dùng:
  python curves/toy_curve_gen.py --selftest
  python curves/toy_curve_gen.py --min-bits 16 --max-bits 40 --step 4 \
         --per-bit 2 --modes prime cofactor --seed 14 --out data/D1_curves.csv
  # dùng như thư viện:
  from curves.toy_curve_gen import generate_curve, Curve
  row = generate_curve(24, mode="prime", seed=1)
  E = Curve.from_row(row); G = Curve.base_point_from_row(row)
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from math import gcd, isqrt
from pathlib import Path
from typing import Dict, List, Optional, Tuple

Point = Optional[Tuple[int, int]]  # None = điểm vô cực O

GENERATION_METHOD = "toy_curve_gen.v1"
NAIVE_COUNT_LIMIT = 1 << 16  # p nhỏ hơn ngưỡng này -> đếm điểm trực tiếp

# Thứ tự cột CSV = thứ tự thuộc tính trong row_schema của D1.
D1_COLUMNS = [
    "curve_id", "p", "a", "b", "discriminant", "discriminant_ok",
    "E_count", "E_count_factorization", "base_point_x", "base_point_y",
    "subgroup_n", "n_bits", "n_factorization", "cofactor_h",
    "largest_prime_factor_n", "is_anomalous", "is_supersingular", "category",
    "source_for_point_class", "small_order_available", "generation_method",
    "seed", "notes", "git_commit", "created_at",
]
_JSON_COLUMNS = {"E_count_factorization", "n_factorization", "small_order_available"}
_BOOL_COLUMNS = {"discriminant_ok", "is_anomalous", "is_supersingular"}
_INT_COLUMNS = {"n_bits", "seed"}


# ---------------------------------------------------------------------------
# 1. Số học cơ bản: nguyên tố, phân tích thừa số, căn bậc hai modulo p
# ---------------------------------------------------------------------------
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    """Miller-Rabin tất định (đúng cho n < 3.3e24)."""
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
        if x in (1, n - 1):
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


def _pollard_rho(n: int) -> int:
    """Trả về một ước nguyên thực sự của hợp số lẻ n (Floyd)."""
    rng = random.Random(n)  # tất định theo n
    while True:
        c = rng.randrange(1, n)
        x = y = rng.randrange(0, n)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
        if d != n:
            return d


def factorize(n: int) -> Dict[int, int]:
    """Phân tích n thành {nguyên tố: số mũ}. Chia thử rồi Pollard rho."""
    if n < 1:
        raise ValueError("n phải >= 1")
    out: Dict[int, int] = {}
    d = 2
    while d < 5000 and d * d <= n:
        while n % d == 0:
            out[d] = out.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2

    def rec(m: int) -> None:
        if m == 1:
            return
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
            return
        f = _pollard_rho(m)
        rec(f)
        rec(m // f)

    rec(n)
    return dict(sorted(out.items()))


def sqrt_mod(n: int, p: int) -> Optional[int]:
    """Căn bậc hai của n modulo p nguyên tố lẻ (Tonelli-Shanks); None nếu không có."""
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


# ---------------------------------------------------------------------------
# 2. Đường cong và phép toán nhóm (toạ độ affine)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Curve:
    """E: y^2 = x^3 + a*x + b trên F_p (p nguyên tố > 3)."""
    p: int
    a: int
    b: int

    def discriminant(self) -> int:
        return (4 * pow(self.a, 3, self.p) + 27 * self.b * self.b) % self.p

    def is_nonsingular(self) -> bool:
        return self.discriminant() != 0

    def rhs(self, x: int) -> int:
        return (x * x * x + self.a * x + self.b) % self.p

    def contains(self, P: Point) -> bool:
        if P is None:
            return True
        x, y = P
        return 0 <= x < self.p and 0 <= y < self.p and (y * y - self.rhs(x)) % self.p == 0

    def neg(self, P: Point) -> Point:
        return None if P is None else (P[0], (-P[1]) % self.p)

    def add(self, P: Point, Q: Point) -> Point:
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(self, k: int, P: Point) -> Point:
        """Nhân vô hướng k*P bằng double-and-add."""
        if k < 0:
            return self.mul(-k, self.neg(P))
        R: Point = None
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def random_point(self, rng: random.Random) -> Tuple[int, int]:
        """Điểm affine ngẫu nhiên (không phải O)."""
        while True:
            x = rng.randrange(self.p)
            y = sqrt_mod(self.rhs(x), self.p)
            if y is not None:
                return (x, y if rng.getrandbits(1) else (-y) % self.p)

    def point_order(self, P: Point, group_order: int,
                    factors: Dict[int, int]) -> int:
        """Bậc của P, biết bội group_order của nó và phân tích thừa số của bội đó."""
        order = group_order
        for q in factors:
            while order % q == 0 and self.mul(order // q, P) is None:
                order //= q
        return order

    # -- (de)serialize với bản ghi D1 -------------------------------------
    @staticmethod
    def from_row(row: dict) -> "Curve":
        return Curve(int(row["p"]), int(row["a"]), int(row["b"]))

    @staticmethod
    def base_point_from_row(row: dict) -> Tuple[int, int]:
        return (int(row["base_point_x"]), int(row["base_point_y"]))


# ---------------------------------------------------------------------------
# 3. Đếm số điểm #E(F_p)
# ---------------------------------------------------------------------------
def count_points_naive(E: Curve) -> int:
    """Đếm trực tiếp O(p) -- chỉ dùng cho p nhỏ / kiểm chứng."""
    sq = Counter(y * y % E.p for y in range(E.p))
    return 1 + sum(sq.get(E.rhs(x), 0) for x in range(E.p))


def _hasse_candidates(E: Curve, P: Tuple[int, int], lo: int, hi: int) -> List[int]:
    """Mọi N trong [lo, hi] thoả N*P = O (baby-step giant-step)."""
    m = isqrt(hi - lo + 1) + 1
    baby: Dict[Point, List[int]] = {}
    R: Point = None
    for j in range(m):
        baby.setdefault(R, []).append(j)  # R = j*P
        R = E.add(R, P)
    giant_step = E.neg(R)                  # -m*P
    T = E.neg(E.mul(lo, P))                # -lo*P
    found: List[int] = []
    for i in range(m):
        for j in baby.get(T, ()):
            N = lo + i * m + j
            if N <= hi:
                found.append(N)
        T = E.add(T, giant_step)
    return found


def count_points_bsgs(E: Curve, rng: Optional[random.Random] = None,
                      max_points: int = 40) -> int:
    """Đếm #E bằng BSGS trên khoảng Hasse [p+1-2sqrt(p), p+1+2sqrt(p)]."""
    rng = rng or random.Random(E.p)
    w = 2 * isqrt(E.p) + 2
    lo, hi = E.p + 1 - w, E.p + 1 + w
    cands: Optional[List[int]] = None
    for _ in range(max_points):
        P = E.random_point(rng)
        if cands is None:
            c = _hasse_candidates(E, P, lo, hi)
            if len(c) > 10000:  # bậc điểm quá nhỏ, thử điểm khác
                continue
            cands = c
        else:
            cands = [N for N in cands if E.mul(N, P) is None]
        if len(cands) == 1:
            return cands[0]
        if not cands:
            raise RuntimeError("count_points_bsgs: không còn ứng viên (lỗi nội bộ)")
    raise RuntimeError("count_points_bsgs: không xác định được duy nhất #E")


def count_points(E: Curve, rng: Optional[random.Random] = None) -> int:
    return count_points_naive(E) if E.p < NAIVE_COUNT_LIMIT else count_points_bsgs(E, rng)


# ---------------------------------------------------------------------------
# 4. Phân loại và dựng bản ghi D1
# ---------------------------------------------------------------------------
def _fact_list(f: Dict[int, int]) -> List[dict]:
    return [{"prime": str(q), "exponent": e} for q, e in f.items()]


def classify(p: int, N: int, n: int, h: int, fn: Dict[int, int],
             smooth_bound: Optional[int]) -> str:
    """Gán category theo enum CurveCategory của schema D1."""
    if N == p:
        return "anomalous"
    if N == p + 1:  # vết t = 0 -> siêu kỳ dị (p > 3)
        return "supersingular"
    n_prime = len(fn) == 1 and next(iter(fn.values())) == 1
    if n_prime and h == 1:
        return "safe_prime_order"
    if n_prime and h > 1:
        return "cofactor_gt1"
    if smooth_bound is not None and max(fn) <= smooth_bound:
        return "smooth_order"
    return "smooth_order" if max(fn) < 1 << 20 else "cofactor_gt1"


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        c = out.stdout.strip()
        if out.returncode == 0 and len(c) >= 7:
            return c
    except Exception:
        pass
    return "0000000"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_row(E: Curve, G: Tuple[int, int], N: int, fN: Dict[int, int],
             n: int, fn: Dict[int, int], seed: int, curve_id: str,
             smooth_bound: Optional[int] = None, notes: Optional[str] = None,
             commit: Optional[str] = None) -> dict:
    h = N // n
    disc = E.discriminant()
    return {
        "curve_id": curve_id,
        "p": str(E.p), "a": str(E.a), "b": str(E.b),
        "discriminant": str(disc), "discriminant_ok": disc != 0,
        "E_count": str(N), "E_count_factorization": _fact_list(fN),
        "base_point_x": str(G[0]), "base_point_y": str(G[1]),
        "subgroup_n": str(n), "n_bits": n.bit_length(),
        "n_factorization": _fact_list(fn),
        "cofactor_h": str(h), "largest_prime_factor_n": str(max(fn)),
        "is_anomalous": N == E.p, "is_supersingular": N == E.p + 1,
        "category": classify(E.p, N, n, h, fn, smooth_bound),
        "source_for_point_class": None, "small_order_available": None,
        "generation_method": GENERATION_METHOD, "seed": seed,
        "notes": notes, "git_commit": commit or git_commit(),
        "created_at": _utc_now(),
    }


# ---------------------------------------------------------------------------
# 5. Bộ sinh đường cong
# ---------------------------------------------------------------------------
MODES = ("prime", "cofactor", "smooth")


def generate_curve(n_bits: int, mode: str = "prime", seed: int = 0,
                   max_cofactor: int = 16, smooth_bound: Optional[int] = None,
                   allow_special: bool = False, max_tries: int = 200000,
                   curve_id: Optional[str] = None) -> dict:
    """
    Sinh một đường cong và trả về bản ghi D1 (dict).
    Tất định: cùng (n_bits, mode, seed, ...) -> cùng đường cong.

    n_bits        : số bit mong muốn của n = ord(G).
    mode          : "prime" | "cofactor" | "smooth".
    max_cofactor  : cận trên của h trong mode "cofactor".
    smooth_bound  : cận B-smooth cho mode "smooth" (mặc định 2^(n_bits//3)).
    allow_special : cho phép đường cong anomalous / supersingular (mặc định loại).
    """
    if mode not in MODES:
        raise ValueError(f"mode phải thuộc {MODES}")
    if n_bits < 8:
        raise ValueError("n_bits phải >= 8")
    if mode == "smooth" and smooth_bound is None:
        smooth_bound = 1 << max(4, n_bits // 3)
    rng = random.Random(seed)
    cid = curve_id or f"crv-{seed & 0xFFFFFFFF:08x}"

    for _ in range(max_tries):
        if mode == "cofactor":
            p_bits = n_bits + rng.randint(1, max(1, max_cofactor.bit_length() - 1))
        else:
            p_bits = n_bits
        p = random_prime(rng, p_bits)
        E = Curve(p, rng.randrange(p), rng.randrange(p))
        if not E.is_nonsingular():
            continue
        try:
            N = count_points(E, rng)
        except RuntimeError:
            continue
        if (N == p or N == p + 1) and not allow_special:
            continue
        fN = factorize(N)
        qmax = max(fN)
        n_prime_part = fN[qmax] == 1

        if mode == "prime":
            if len(fN) != 1 or fN[qmax] != 1 or N.bit_length() != n_bits:
                continue
            n, fn = N, fN
            G = E.random_point(rng)
        elif mode == "cofactor":
            h = N // qmax
            if not n_prime_part or not (2 <= h <= max_cofactor) or qmax.bit_length() != n_bits:
                continue
            n, fn = qmax, {qmax: 1}
            P = E.random_point(rng)
            G = E.mul(h, P)
            if G is None:
                continue
        else:  # smooth
            if qmax > smooth_bound or N.bit_length() < n_bits:
                continue
            best, best_n = None, 0
            for _t in range(20):  # chọn điểm có bậc lớn nhất trong vài mẫu
                P = E.random_point(rng)
                o = E.point_order(P, N, fN)
                if o > best_n:
                    best, best_n = P, o
            n = best_n
            if n.bit_length() != n_bits or len(factorize(n)) < 2:
                continue
            fn, G = factorize(n), best
        return make_row(E, G, N, fN, n, fn, seed, cid,
                        smooth_bound=smooth_bound,
                        notes=f"mode={mode}")
    raise RuntimeError(f"Không sinh được curve (n_bits={n_bits}, mode={mode}) sau {max_tries} lần thử")


# ---------------------------------------------------------------------------
# 6. Kiểm chứng toán học một bản ghi D1
# ---------------------------------------------------------------------------
def verify_row(row: dict, recount: bool = True) -> List[str]:
    """Trả về danh sách lỗi (rỗng = hợp lệ). Hoạt động với row dict hoặc dòng CSV đã parse."""
    row = parse_csv_row(row) if isinstance(row.get("discriminant_ok"), str) else row
    errs: List[str] = []
    p, a, b = int(row["p"]), int(row["a"]), int(row["b"])
    E = Curve(p, a, b)
    N, n, h = int(row["E_count"]), int(row["subgroup_n"]), int(row["cofactor_h"])
    G = Curve.base_point_from_row(row)
    if not is_prime(p) or p <= 3:
        errs.append("p không phải số nguyên tố > 3")
    if not E.is_nonsingular() or str(E.discriminant()) != str(row["discriminant"]):
        errs.append("discriminant sai hoặc curve suy biến")
    if not E.contains(G):
        errs.append("G không nằm trên curve")
    if E.mul(n, G) is not None:
        errs.append("n*G != O")
    fn = {int(f["prime"]): f["exponent"] for f in row["n_factorization"]}
    fN = {int(f["prime"]): f["exponent"] for f in row["E_count_factorization"]}
    for q in fn:
        if not is_prime(q):
            errs.append(f"thừa số {q} của n không nguyên tố")
        elif E.mul(n // q, G) is None:
            errs.append(f"bậc của G nhỏ hơn n (chia hết cho {q} lần nữa)")
    prod = lambda f: __import__("math").prod(q ** e for q, e in f.items())
    if prod(fn) != n:
        errs.append("n_factorization không nhân lại ra n")
    if prod(fN) != N:
        errs.append("E_count_factorization không nhân lại ra #E")
    if n * h != N:
        errs.append("n * h != #E")
    if n.bit_length() != int(row["n_bits"]):
        errs.append("n_bits sai")
    if str(max(fn)) != str(row["largest_prime_factor_n"]):
        errs.append("largest_prime_factor_n sai")
    if bool(row["is_anomalous"]) != (N == p) or bool(row["is_supersingular"]) != (N == p + 1):
        errs.append("cờ anomalous/supersingular sai")
    if abs(N - (p + 1)) > 2 * isqrt(p) + 2:
        errs.append("#E vi phạm cận Hasse")
    if recount and count_points(E) != N:
        errs.append("đếm lại #E không khớp")
    return errs


# ---------------------------------------------------------------------------
# 7. Đọc / ghi CSV theo chuẩn D1
# ---------------------------------------------------------------------------
def _to_cell(col: str, v):
    if v is None:
        return ""
    if col in _JSON_COLUMNS:
        return json.dumps(v, separators=(",", ":"))
    if col in _BOOL_COLUMNS:
        return "true" if v else "false"
    return str(v)


def parse_csv_row(raw: dict) -> dict:
    """Dòng csv.DictReader -> dict đúng kiểu như make_row."""
    row: dict = {}
    for col in D1_COLUMNS:
        v = raw.get(col, "")
        if col in _JSON_COLUMNS:
            row[col] = json.loads(v) if v else None
        elif col in _BOOL_COLUMNS:
            row[col] = v.strip().lower() == "true"
        elif col in _INT_COLUMNS:
            row[col] = int(v)
        else:
            row[col] = v if v != "" else None
    return row


def write_csv(rows: List[dict], path: str, append: bool = False) -> None:
    path_ = Path(path)
    path_.parent.mkdir(parents=True, exist_ok=True)
    exists = append and path_.exists() and path_.stat().st_size > 0
    with open(path_, "a" if exists else "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(D1_COLUMNS)
        for r in rows:
            w.writerow([_to_cell(c, r.get(c)) for c in D1_COLUMNS])


def load_csv(path: str) -> List[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return [parse_csv_row(r) for r in csv.DictReader(f)]


def _next_index(path: str) -> int:
    """Chỉ số curve_id kế tiếp khi --append."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return 0
    ids = [int(r["curve_id"].split("-")[1], 16) for r in load_csv(path)]
    return max(ids) + 1 if ids else 0


# ---------------------------------------------------------------------------
# 8. Selftest và CLI
# ---------------------------------------------------------------------------
def selftest() -> bool:
    ok = True
    rng = random.Random(2024)
    print("[1] So khớp đếm điểm: naive vs BSGS (p ~ 2^14..2^20)")
    for bits in (14, 17, 20):
        for _ in range(3):
            p = random_prime(rng, bits)
            E = Curve(p, rng.randrange(p), rng.randrange(p))
            if not E.is_nonsingular():
                continue
            n1, n2 = count_points_naive(E), count_points_bsgs(E, rng)
            good = n1 == n2
            ok &= good
            print(f"    p={p:>8} #E naive={n1} bsgs={n2} {'OK' if good else 'FAIL'}")
    print("[2] Phân tích thừa số")
    for v in (2**31 - 1, 600851475143, 999999000001 * 3):
        f = factorize(v)
        good = __import__("math").prod(q ** e for q, e in f.items()) == v
        ok &= good
        print(f"    {v} = {f} {'OK' if good else 'FAIL'}")
    print("[3] Sinh + kiểm chứng curve từng mode")
    for mode, bits in (("prime", 16), ("prime", 28), ("cofactor", 20), ("smooth", 24)):
        row = generate_curve(bits, mode=mode, seed=7 + bits)
        errs = verify_row(row)
        ok &= not errs
        print(f"    {mode:<8} n_bits={row['n_bits']:<3} p={row['p']:<12} "
              f"n={row['subgroup_n']:<12} h={row['cofactor_h']:<3} "
              f"cat={row['category']:<17} {'OK' if not errs else errs}")
    print("[4] Tính tất định theo seed")
    r1, r2 = generate_curve(20, "prime", seed=5), generate_curve(20, "prime", seed=5)
    same = all(r1[k] == r2[k] for k in ("p", "a", "b", "base_point_x", "base_point_y"))
    ok &= same
    print(f"    {'OK' if same else 'FAIL'}")
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return ok


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Sinh toy elliptic curve trên F_p (D1).")
    ap.add_argument("--selftest", action="store_true", help="chạy kiểm thử nội bộ rồi thoát")
    ap.add_argument("--min-bits", type=int, default=16)
    ap.add_argument("--max-bits", type=int, default=40)
    ap.add_argument("--step", type=int, default=4)
    ap.add_argument("--per-bit", type=int, default=1, help="số curve cho mỗi (mode, n_bits)")
    ap.add_argument("--modes", nargs="+", choices=MODES, default=["prime"])
    ap.add_argument("--max-cofactor", type=int, default=16)
    ap.add_argument("--smooth-bound", type=int, default=None)
    ap.add_argument("--seed", type=int, default=14, help="seed gốc")
    ap.add_argument("--out", default=None, help="file CSV đầu ra (vd data/D1_curves.csv)")
    ap.add_argument("--append", action="store_true", help="ghi nối vào file có sẵn")
    ap.add_argument("--no-verify", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return 0 if selftest() else 1

    idx = _next_index(args.out) if (args.out and args.append) else 0
    commit = git_commit()
    rows: List[dict] = []
    for mode in args.modes:
        for bits in range(args.min_bits, args.max_bits + 1, args.step):
            for _ in range(args.per_bit):
                seed = args.seed * 1_000_003 + idx
                row = generate_curve(bits, mode, seed=seed,
                                     max_cofactor=args.max_cofactor,
                                     smooth_bound=args.smooth_bound,
                                     curve_id=f"crv-{idx:08x}")
                row["git_commit"] = commit
                if not args.no_verify:
                    errs = verify_row(row, recount=False)
                    if errs:
                        print(f"LỖI {row['curve_id']}: {errs}", file=sys.stderr)
                        return 1
                rows.append(row)
                print(f"{row['curve_id']} {mode:<8} n_bits={row['n_bits']:<3} "
                      f"p={row['p']} #E={row['E_count']} h={row['cofactor_h']} "
                      f"[{row['category']}]")
                idx += 1
    if args.out:
        write_csv(rows, args.out, append=args.append)
        print(f"Đã ghi {len(rows)} curve -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
