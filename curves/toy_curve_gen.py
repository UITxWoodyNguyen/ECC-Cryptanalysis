"""
curves/toy_curve_gen.py -- Module sinh đường cong Elliptic "toy" trên F_p
=========================================================================
Topic 14: ECC Cryptanalysis -- Track A (generic ECDLP search).

Tái sử dụng trực tiếp nền tảng toán học & phép toán nhóm từ `curves/ecc.py`
(ECC, Point, FindOrder, is_prime, random_prime, sqrt_mod, factorint).
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from math import isqrt, prod
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Tự động thêm thư mục gốc dự án vào sys.path để chạy được từ mọi vị trí
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from curves.ecc import (
    ECC,
    Point,
    FindOrder,
    is_prime,
    random_prime,
    sqrt_mod,
    factorint as factorize,
)

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
# 1. Helper chuyển đổi bản ghi D1 <-> (ECC, Point) từ curves/ecc.py
# ---------------------------------------------------------------------------
def curve_from_row(row: dict) -> ECC:
    return ECC(int(row["a"]), int(row["b"]), int(row["p"]))


def base_point_from_row(row: dict, curve: Optional[ECC] = None) -> Point:
    E = curve or curve_from_row(row)
    return Point(E, int(row["base_point_x"]), int(row["base_point_y"]))


# ---------------------------------------------------------------------------
# 2. Đếm số điểm #E(F_p) sử dụng trực tiếp ECC & Point
# ---------------------------------------------------------------------------
def count_points_naive(E: ECC) -> int:
    """Đếm trực tiếp O(p) -- chỉ dùng cho p nhỏ / kiểm chứng."""
    sq = Counter(y * y % E.p for y in range(E.p))
    return 1 + sum(sq.get(E.rhs(x), 0) for x in range(E.p))


def _hasse_candidates(E: ECC, P: Point, lo: int, hi: int) -> List[int]:
    """Mọi N trong [lo, hi] thoả N*P = O (baby-step giant-step)."""
    m = isqrt(hi - lo + 1) + 1
    baby: Dict[Point, List[int]] = {}
    R = Point(E, is_infinity=True)
    for j in range(m):
        baby.setdefault(R, []).append(j)  # R = j*P
        R = R + P
    giant_step = -R                        # -m*P
    T = -(lo * P)                          # -lo*P
    found: List[int] = []
    for i in range(m):
        for j in baby.get(T, ()):
            N = lo + i * m + j
            if N <= hi:
                found.append(N)
        T = T + giant_step
    return found


def count_points_bsgs(E: ECC, rng: Optional[random.Random] = None,
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
            cands = [N for N in cands if (N * P).is_infinity]
        if len(cands) == 1:
            return cands[0]
        if not cands:
            raise RuntimeError("count_points_bsgs: không còn ứng viên (lỗi nội bộ)")
    raise RuntimeError("count_points_bsgs: không xác định được duy nhất #E")


def count_points(E: ECC, rng: Optional[random.Random] = None) -> int:
    return count_points_naive(E) if E.p < NAIVE_COUNT_LIMIT else count_points_bsgs(E, rng)


# ---------------------------------------------------------------------------
# 3. Phân loại và dựng bản ghi D1
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


def make_row(E: ECC, G: Point, N: int, fN: Dict[int, int],
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
        "base_point_x": str(G.x), "base_point_y": str(G.y),
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
# 4. Bộ sinh đường cong
# ---------------------------------------------------------------------------
MODES = ("prime", "cofactor", "smooth")


def generate_curve(n_bits: int, mode: str = "prime", seed: int = 0,
                   max_cofactor: int = 16, smooth_bound: Optional[int] = None,
                   allow_special: bool = False, max_tries: int = 200000,
                   curve_id: Optional[str] = None) -> dict:
    """
    Sinh một đường cong và trả về bản ghi D1 (dict).
    Tất định: cùng (n_bits, mode, seed, ...) -> cùng đường cong.
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
        E = ECC(rng.randrange(p), rng.randrange(p), p)
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
            G = h * P
            if G.is_infinity:
                continue
        else:  # smooth
            if qmax > smooth_bound or N.bit_length() < n_bits:
                continue
            best, best_n = None, 0
            for _t in range(20):
                P = E.random_point(rng)
                o = FindOrder(P, group_order_hint=N)
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
# 5. Kiểm chứng toán học một bản ghi D1
# ---------------------------------------------------------------------------
def verify_row(row: dict, recount: bool = True) -> List[str]:
    """Trả về danh sách lỗi (rỗng = hợp lệ)."""
    row = parse_csv_row(row) if isinstance(row.get("discriminant_ok"), str) else row
    errs: List[str] = []
    E = curve_from_row(row)
    p = E.p
    N, n, h = int(row["E_count"]), int(row["subgroup_n"]), int(row["cofactor_h"])
    G = base_point_from_row(row, E)
    if not is_prime(p) or p <= 3:
        errs.append("p không phải số nguyên tố > 3")
    if not E.is_nonsingular() or str(E.discriminant()) != str(row["discriminant"]):
        errs.append("discriminant sai hoặc curve suy biến")
    if G.is_infinity or not (0 <= G.x < p and 0 <= G.y < p and E.is_on_curve(G.x, G.y)):
        errs.append("G không nằm trên curve")
    if not (n * G).is_infinity:
        errs.append("n*G != O")
    fn = {int(f["prime"]): f["exponent"] for f in row["n_factorization"]}
    fN = {int(f["prime"]): f["exponent"] for f in row["E_count_factorization"]}
    for q in fn:
        if not is_prime(q):
            errs.append(f"thừa số {q} của n không nguyên tố")
        elif ((n // q) * G).is_infinity:
            errs.append(f"bậc của G nhỏ hơn n (chia hết cho {q} lần nữa)")
    if prod(q ** e for q, e in fn.items()) != n:
        errs.append("n_factorization không nhân lại ra n")
    if prod(q ** e for q, e in fN.items()) != N:
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
# 6. Đọc / ghi CSV theo chuẩn D1
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
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return 0
    ids = [int(r["curve_id"].split("-")[1], 16) for r in load_csv(path)]
    return max(ids) + 1 if ids else 0


# ---------------------------------------------------------------------------
# 7. Selftest và CLI
# ---------------------------------------------------------------------------
def selftest() -> bool:
    ok = True
    rng = random.Random(2024)
    print("[1] So khớp đếm điểm: naive vs BSGS (p ~ 2^14..2^20)")
    for bits in (14, 17, 20):
        for _ in range(3):
            p = random_prime(rng, bits)
            E = ECC(rng.randrange(p), rng.randrange(p), p)
            if not E.is_nonsingular():
                continue
            n1, n2 = count_points_naive(E), count_points_bsgs(E, rng)
            good = n1 == n2
            ok &= good
            print(f"    p={p:>8} #E naive={n1} bsgs={n2} {'OK' if good else 'FAIL'}")
    print("[2] Phân tích thừa số")
    for v in (2**31 - 1, 600851475143, 999999000001 * 3):
        f = factorize(v)
        good = prod(q ** e for q, e in f.items()) == v
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