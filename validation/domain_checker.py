"""
validation/domain_checker.py
=============================

**Domain Parameter Checker** — kiểm tra các điều kiện cấu trúc an toàn của
domain parameters (p, a, b, G, n, h) theo đúng checklist 10 mục trong
`curves/math_notes.md` §6. Đây KHÔNG phải công cụ tấn công — là validator
"offline" chạy một lần trên tham số của 1 curve, trả về báo cáo
PASS / WARN / FAIL / INFO cho từng điều kiện.

Dùng ở đâu:
    - Gate các toy curve do `curves/gen_smooth_curves.py`,
      `validation/gen_invalid_curves.py` sinh ra TRƯỚC khi đưa vào thí
      nghiệm — phân biệt "curve cố ý yếu để demo" (đã biết, có nhãn) với
      "curve bị lỗi do sinh nhầm" (bug, cần loại bỏ).
    - Negative control: chạy trên P-256 (và các curve named khác) để xác
      nhận domain parameters theo chuẩn KHÔNG vi phạm điều kiện nào
      (docs/negative_controls.md).
    - Bước đầu của mọi thí nghiệm Track A trước khi benchmark (phát hiện
      sớm nếu `gen_toy_curve.py`/`gen_smooth_curves.py` sinh lỗi).

Ánh xạ 10 mục trong curves/math_notes.md §6 -> các check trong module này:
    #1 Δ≠0                      -> discriminant_nonzero
    #2 p nguyên tố; G on-curve  -> field_p_prime + base_point_on_curve
    #3 n nguyên tố (hoặc q_max) -> subgroup_order_primality
    #4 nG=O và G≠O              -> base_point_order_exact
    #5 #E≠p                     -> not_anomalous
    #6 embedding degree k       -> embedding_degree_sufficient
    #7 h nhỏ, biết cách xử lý   -> cofactor_acceptable
    #8 Twist security           -> twist_security
    #9 Hasse                    -> hasse_bound_consistency
    #10 named/approved          -> named_or_approved_allowlist
    (bổ sung, không có số thứ tự riêng trong math_notes nhưng hữu ích để
     bắt lỗi sinh curve)         -> trace_zero_heuristic, e_count_self_consistency
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass, field
from math import isqrt
from typing import Any, Dict, List, Optional, Tuple

# --- Import số học điểm dùng chung từ signatures/base_signer.py -----------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from signatures.base_signer import (  # type: ignore
        CurveParams, Point, curve_from_d1_record, get_curve,
        CURVE_REGISTRY, point_add, point_neg, scalar_mult, is_on_curve,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "domain_checker.py cần signatures/base_signer.py cùng project-root "
        "(validation/ và signatures/ phải là 2 thư mục anh em). "
        f"Lỗi gốc: {exc}"
    ) from exc

__all__ = [
    "CheckStatus",
    "CheckResult",
    "DomainParameterReport",
    "is_probable_prime",
    "trial_division_factors",
    "embedding_degree",
    "count_points_naive",
    "check_domain_parameters",
]


# ---------------------------------------------------------------------------
# 0. Tiện ích toán học nền (tự chứa, không phụ thuộc sympy)
# ---------------------------------------------------------------------------

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin xác suất, rounds=40 -> xác suất sai ~ 4^-40, đủ dùng cho
    mọi mục đích thực tế (không claim bằng chứng toán học tuyệt đối)."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(1234567891)  # seed cố định -> kết quả tái lập được
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def trial_division_factors(n: int, bound: int = 10 ** 6) -> Tuple[List[Tuple[int, int]], int]:
    """Trial division các số nguyên tố <= bound.

    Trả về (factors, remainder):
      - factors: danh sách (prime, exponent) các ước <= bound tìm được, CỘNG
        với ước còn lại nếu nó <= bound^2 (khi đó CHẮC CHẮN là số nguyên tố,
        vì nếu remainder hợp số với mọi ước > bound thì remainder > bound^2).
      - remainder: phần chưa factor được (==1 nếu đã factor hoàn toàn).
    """
    factors: List[Tuple[int, int]] = []
    m = n
    if m <= 1:
        return factors, m
    for p in (2, 3):
        if p <= bound:
            e = 0
            while m % p == 0:
                m //= p
                e += 1
            if e:
                factors.append((p, e))
    p = 5
    step = 2  # thử 5,7,11,13,... (bỏ qua bội của 2,3) theo mẫu 6k±1
    toggle = 0
    while p <= bound and p * p <= m:
        if m % p == 0:
            e = 0
            while m % p == 0:
                m //= p
                e += 1
            factors.append((p, e))
        p += (2, 4)[toggle]
        toggle ^= 1
    if m > 1 and m <= bound * bound and is_probable_prime(m):
        factors.append((m, 1))
        m = 1
    return factors, m


def _scalar_mult_raw(curve: "CurveParams", k: int, P: "Point") -> "Point":
    """Nhân vô hướng double-and-add KHÔNG rút gọn k theo curve.n.

    QUAN TRỌNG: signatures.base_signer.scalar_mult() chủ động rút gọn
    `k %= curve.n` (hợp lý khi ký/ECDH vì n được GIẢ ĐỊNH là đúng). Nhưng khi
    domain_checker cần tự kiểm "n có thực sự là bậc của G không", dùng hàm
    rút-gọn-sẵn đó sẽ khiến `scalar_mult(curve, n, G)` LUÔN trả về O một cách
    giả tạo (vì k=n -> k%n=0) bất kể n có đúng hay không — một phép kiểm vô
    nghĩa (tautology). Hàm này tồn tại riêng để tránh lỗi logic đó.
    """
    if P is None or k == 0:
        return None
    if k < 0:
        return _scalar_mult_raw(curve, -k, point_neg(curve, P))
    R: "Point" = None
    Q: "Point" = P
    kk = k
    while kk:
        if kk & 1:
            R = point_add(curve, R, Q)
        Q = point_add(curve, Q, Q)
        kk >>= 1
    return R


def largest_prime_factor(factors: List[Tuple[int, int]]) -> Optional[int]:
    return max((p for p, _ in factors), default=None)


def embedding_degree(p: int, n: int, k_max: int = 50) -> Optional[int]:
    """Bậc nhỏ nhất k sao cho n | (p^k - 1), tức DLP trên E(F_p)[n] nhúng được
    vào F_{p^k}* (MOV/Frey–Rück). None nếu không tìm thấy trong [1, k_max]
    (coi là 'đủ an toàn' theo ngưỡng tìm kiếm này)."""
    if n <= 1:
        return None
    for k in range(1, k_max + 1):
        if pow(p, k, n) == 1:
            return k
    return None


def count_points_naive(curve: "CurveParams") -> int:
    """Đếm #E(F_p) trực tiếp bằng ký hiệu Legendre (Euler's criterion),
    O(p) phép modpow — chỉ khả thi với p nhỏ (toy curve). Dùng để tự kiểm
    tính nhất quán của subgroup_n*cofactor_h do script sinh curve khai báo."""
    p, a, b = curve.p, curve.a, curve.b
    count = 1  # điểm tại vô cực
    for x in range(p):
        rhs = (x ** 3 + a * x + b) % p
        if rhs == 0:
            count += 1
        else:
            ls = pow(rhs, (p - 1) // 2, p)
            if ls == 1:
                count += 2
            # ls == p-1 (phi-thặng dư bậc 2): không có điểm, không cộng gì
    return count


# ---------------------------------------------------------------------------
# 1. Cấu trúc báo cáo
# ---------------------------------------------------------------------------

class CheckStatus:
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"

    _SEVERITY = {"PASS": 0, "INFO": 0, "WARN": 1, "FAIL": 2}

    @classmethod
    def worse(cls, a: str, b: str) -> str:
        return a if cls._SEVERITY[a] >= cls._SEVERITY[b] else b


@dataclass
class CheckResult:
    check_id: str
    name: str
    status: str
    detail: str
    value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id, "name": self.name,
            "status": self.status, "detail": self.detail, "value": self.value,
        }


@dataclass
class DomainParameterReport:
    curve_name: str
    checks: List[CheckResult] = field(default_factory=list)

    def add(self, check_id: str, name: str, status: str, detail: str, value: Any = None) -> None:
        self.checks.append(CheckResult(check_id, name, status, detail, value))

    @property
    def overall_status(self) -> str:
        status = CheckStatus.PASS
        for c in self.checks:
            status = CheckStatus.worse(status, c.status)
        return status

    def get(self, check_id: str) -> Optional[CheckResult]:
        return next((c for c in self.checks if c.check_id == check_id), None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "curve_name": self.curve_name,
            "overall_status": self.overall_status,
            "checks": [c.to_dict() for c in self.checks],
        }

    def print_report(self) -> None:
        print(f"== Domain Parameter Report: {self.curve_name} "
              f"(overall = {self.overall_status}) ==")
        for c in self.checks:
            print(f"  [{c.status:4s}] {c.check_id:28s} {c.detail}")

    def to_markdown_table(self) -> str:
        lines = [
            f"### Domain Parameter Report — `{self.curve_name}` "
            f"(overall: **{self.overall_status}**)",
            "",
            "| # | Check | Trạng thái | Chi tiết |",
            "|---|-------|------------|----------|",
        ]
        for i, c in enumerate(self.checks, start=1):
            lines.append(f"| {i} | {c.name} | {c.status} | {c.detail} |")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. Hàm chính: check_domain_parameters
# ---------------------------------------------------------------------------

def check_domain_parameters(
    curve_input,
    *,
    E_count: Optional[int] = None,
    allow_list: Optional[Dict[str, "CurveParams"]] = None,
    small_factor_bound: int = 10 ** 6,
    embedding_k_max: int = 50,
    k_warn_below: int = 6,
    twist_small_factor_bound: int = 10 ** 6,
    brute_force_point_count_limit: int = 200_000,
) -> DomainParameterReport:
    """Chạy toàn bộ checklist domain parameters trên 1 curve.

    curve_input: CurveParams, tên curve đã đăng ký ('P-256'), hoặc dict bản
                 ghi D1 (data/D1_curves.csv) — xem signatures.base_signer.get_curve.
    E_count:     #E(F_p) nếu đã biết từ trước (vd ghi sẵn trong D1); nếu None,
                 suy ra bằng n*h (giả định n, h trong curve_input đã đúng —
                 các check #5/#9/e_count_self_consistency sẽ tự phát hiện nếu
                 giả định này sai).
    allow_list:  dict {tên: CurveParams} để so khớp check #10; mặc định dùng
                 CURVE_REGISTRY từ signatures.base_signer (gồm P-256).
    """
    curve = get_curve(curve_input)
    report = DomainParameterReport(curve_name=curve.name)

    p, a, b, n, h, G = curve.p, curve.a, curve.b, curve.n, curve.h, curve.G

    if E_count is None:
        E_count = n * h  # giả định n, h đã đúng; sẽ bị check #9/#extra bắt lỗi nếu sai
        e_count_source = "derived=n*h"
    else:
        e_count_source = "provided"

    # --- Check #1: discriminant --------------------------------------------
    disc = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
    if disc == 0:
        report.add("discriminant_nonzero", "Δ ≠ 0 (không singular)",
                    CheckStatus.FAIL, f"Δ=4a³+27b²={disc} mod p == 0 -> curve SINGULAR, "
                    f"không phải nhóm elliptic.", value=disc)
    else:
        report.add("discriminant_nonzero", "Δ ≠ 0 (không singular)",
                    CheckStatus.PASS, f"Δ={disc} mod p ≠ 0.", value=disc)

    # --- Check #2a: p nguyên tố ---------------------------------------------
    p_prime = is_probable_prime(p)
    report.add("field_p_prime", "p nguyên tố (Miller-Rabin)",
                CheckStatus.PASS if p_prime else CheckStatus.FAIL,
                f"p {'là' if p_prime else 'KHÔNG phải là'} số nguyên tố (p.bit_length()={p.bit_length()}).",
                value=p_prime)

    # --- Check #2b: G on-curve ------------------------------------------------
    g_on_curve = is_on_curve(curve, G) and G is not None
    report.add("base_point_on_curve", "G nằm trên curve",
                CheckStatus.PASS if g_on_curve else CheckStatus.FAIL,
                "G thoả y²=x³+ax+b (mod p)." if g_on_curve else "G KHÔNG thoả phương trình curve.",
                value=g_on_curve)

    # --- Check #3: n nguyên tố (hoặc báo q_max) --------------------------------
    n_factors, n_remainder = trial_division_factors(n, bound=small_factor_bound)
    n_fully_factored = (n_remainder == 1)
    n_is_prime = n_fully_factored and len(n_factors) == 1 and n_factors[0][1] == 1
    q_max = largest_prime_factor(n_factors) if n_factors else None
    if n_is_prime:
        report.add("subgroup_order_primality", "n nguyên tố",
                    CheckStatus.PASS, f"n là số nguyên tố (n.bit_length()={n.bit_length()}).",
                    value={"factors": n_factors, "remainder": n_remainder})
    elif n_fully_factored:
        report.add("subgroup_order_primality", "n nguyên tố (hoặc q_max đủ lớn)",
                    CheckStatus.FAIL,
                    f"n KHÔNG nguyên tố, n={_fmt_factors(n_factors)}; "
                    f"q_max={q_max} -> Pohlig–Hellman có work ≈ O(√q_max) thay vì O(√n).",
                    value={"factors": n_factors, "q_max": q_max})
    else:
        if q_max and q_max.bit_length() < n.bit_length() - 20:
            status = CheckStatus.WARN
            detail = (f"Tìm thấy ước nhỏ {_fmt_factors(n_factors)} (chưa factor hết, "
                      f"phần dư {n_remainder.bit_length()} bit); nếu phần dư KHÔNG "
                      f"nguyên tố, n có thể còn ước nhỏ hơn q_max={q_max} đã biết.")
        else:
            status = CheckStatus.PASS
            detail = (f"Không tìm thấy ước nguyên tố <= {small_factor_bound:,} của n "
                      f"(n.bit_length()={n.bit_length()}); coi n 'đủ nguyên tố' theo "
                      f"ngưỡng trial division này (KHÔNG phải bằng chứng n nguyên tố tuyệt đối).")
        report.add("subgroup_order_primality", "n nguyên tố (hoặc q_max đủ lớn)",
                    status, detail, value={"factors": n_factors, "remainder_bits": n_remainder.bit_length()})

    # --- Check #4: n*G = O và G thực sự có bậc đúng n --------------------------
    # Dùng _scalar_mult_raw (KHÔNG rút gọn k mod n) — xem docstring hàm đó để
    # hiểu vì sao dùng scalar_mult thường ở đây sẽ cho kết quả giả tạo.
    nG = _scalar_mult_raw(curve, n, G)
    n_times_g_is_infinity = (nG is None)
    exact_order_checked = False
    exact_order_ok = None
    if n_times_g_is_infinity and n_fully_factored and n_factors:
        exact_order_checked = True
        exact_order_ok = True
        for q, _ in n_factors:
            if _scalar_mult_raw(curve, n // q, G) is None:
                exact_order_ok = False
                break
    if not n_times_g_is_infinity:
        report.add("base_point_order_exact", "n·G = O",
                    CheckStatus.FAIL, "n·G != O -> n KHÔNG phải bậc đúng của G (tham số sai).",
                    value=False)
    elif exact_order_checked and not exact_order_ok:
        report.add("base_point_order_exact", "n·G = O và bậc G đúng bằng n",
                    CheckStatus.FAIL,
                    "n·G = O nhưng tồn tại ước thực sự q|n với (n/q)·G cũng = O "
                    "-> bậc thật của G là ước của n, không phải n (tham số sai hoặc G chọn sai).",
                    value=False)
    else:
        detail = "n·G = O."
        if exact_order_checked:
            detail += " Đã xác nhận bậc G đúng bằng n (kiểm mọi ước nguyên tố q|n)."
        else:
            detail += (" Không factor được n hoàn toàn trong ngưỡng trial division "
                       "-> chỉ xác nhận n là BỘI của bậc G, không khẳng định bậc đúng bằng n "
                       "(chấp nhận được với curve named/chuẩn đã certify).")
        report.add("base_point_order_exact", "n·G = O (và bậc G đúng n nếu factor được)",
                    CheckStatus.PASS, detail, value=True)

    # --- Check #5: #E != p (không anomalous) -----------------------------------
    is_anomalous = (E_count == p)
    report.add("not_anomalous", "#E ≠ p (không anomalous)",
                CheckStatus.FAIL if is_anomalous else CheckStatus.PASS,
                ("#E == p -> ANOMALOUS CURVE, Smart's attack giải ECDLP trong thời gian "
                 "ĐA THỨC." if is_anomalous else f"#E={E_count} != p -> không anomalous."),
                value=is_anomalous)

    # --- Check bổ sung: trace-zero heuristic (#E == p+1) ------------------------
    trace = p + 1 - E_count
    is_trace_zero = (trace == 0)
    report.add("trace_zero_heuristic", "#E ≠ p+1 (heuristic supersingular)",
                CheckStatus.WARN if is_trace_zero else CheckStatus.PASS,
                ("#E == p+1 (trace t=0) -> MỘT trường hợp supersingular phổ biến; "
                 "cần kiểm thêm embedding degree (check #6)." if is_trace_zero
                 else f"trace t=p+1-#E={trace} != 0 -> không khớp mẫu supersingular trace-zero."),
                value=trace)

    # --- Check #6: embedding degree --------------------------------------------
    k = embedding_degree(p, n, k_max=embedding_k_max)
    if k is None:
        report.add("embedding_degree_sufficient", "Embedding degree k đủ lớn",
                    CheckStatus.PASS, f"Không tìm thấy k <= {embedding_k_max} với n | (p^k - 1) "
                    f"-> k > {embedding_k_max}, coi là an toàn trước MOV/Frey–Rück.", value=None)
    elif k <= k_warn_below:
        report.add("embedding_degree_sufficient", "Embedding degree k đủ lớn",
                    CheckStatus.FAIL, f"k={k} <= ngưỡng cảnh báo ({k_warn_below}) -> "
                    f"ECDLP trên E chuyển được (MOV/Frey–Rück) về DLP trong F_(p^{k})*, "
                    f"khả năng bị phá nếu p^{k} đủ nhỏ.", value=k)
    else:
        report.add("embedding_degree_sufficient", "Embedding degree k đủ lớn",
                    CheckStatus.WARN, f"k={k} (>{k_warn_below} nên không FAIL, nhưng vẫn nên "
                    f"xác nhận p^k đủ lớn để MOV vô dụng).", value=k)

    # --- Check #7: cofactor h ----------------------------------------------------
    if h == 1:
        report.add("cofactor_acceptable", "Cofactor h nhỏ & có cách xử lý",
                    CheckStatus.PASS, "h=1 -> mọi điểm on-curve (≠O) tự động thuộc ⟨G⟩, "
                    "không cần subgroup check riêng.", value=h)
    elif h >= n or h.bit_length() > 8:
        # h >= n: phần lớn (hoặc gần hết) #E nằm NGOÀI ⟨G⟩ -> cấu trúc đáng ngờ,
        # không chỉ là "cần subgroup check" mà bản thân lựa chọn G/n đã kém.
        # h.bit_length() > 8: cofactor lớn hơn hẳn các giá trị named-curve thường gặp (1,4,8).
        report.add("cofactor_acceptable", "Cofactor h nhỏ & có cách xử lý",
                    CheckStatus.FAIL,
                    f"h={h} {'>= n='+str(n)+' -> phần lớn #E nằm ngoài ⟨G⟩, cấu trúc đáng ngờ' if h >= n else f'quá lớn ({h.bit_length()} bit)'}.",
                    value=h)
    else:  # 1 < h < n, h nhỏ (vd 2,4,8 — Curve25519 h=8, Curve448 h=4)
        report.add("cofactor_acceptable", "Cofactor h nhỏ & có cách xử lý",
                    CheckStatus.WARN, f"h={h} > 1 -> BẮT BUỘC subgroup check hoặc cofactor "
                    f"clearing ở tầng validation (xem Track D); nếu thiếu, dễ bị "
                    f"small-subgroup attack.", value=h)

    # --- Check #8: twist security --------------------------------------------------
    twist_order = 2 * (p + 1) - E_count
    if twist_order <= 1:
        report.add("twist_security", "Twist security",
                    CheckStatus.WARN, f"twist_order={twist_order} bất thường (<=1), "
                    f"bỏ qua kiểm tra twist (có thể #E cung cấp sai).", value=twist_order)
    else:
        t_factors, t_remainder = trial_division_factors(twist_order, bound=twist_small_factor_bound)
        t_fully_factored = (t_remainder == 1)
        t_q_max = largest_prime_factor(t_factors) if t_factors else None
        twist_safety_bits = (t_remainder.bit_length() if not t_fully_factored
                              else (t_q_max.bit_length() if t_q_max else 0))
        if t_fully_factored and t_q_max and t_q_max.bit_length() < twist_order.bit_length() - 20:
            report.add("twist_security", "Twist security",
                        CheckStatus.FAIL, f"#E_twist={_fmt_factors(t_factors)} SMOOTH "
                        f"(q_max={t_q_max}, chỉ {t_q_max.bit_length()} bit) -> twist attack "
                        f"khả thi nếu giao thức không kiểm tra điểm thuộc đúng curve gốc.",
                        value={"twist_order_bits": twist_order.bit_length(), "t_q_max": t_q_max})
        elif twist_safety_bits < twist_order.bit_length() - 20:
            report.add("twist_security", "Twist security",
                        CheckStatus.WARN, f"Chưa factor hết #E_twist (ước lớn nhất tìm được/"
                        f"phần dư ~{twist_safety_bits} bit trên tổng {twist_order.bit_length()} "
                        f"bit) -> cần xác nhận thêm bằng công cụ chuyên dụng (Sage/PARI) trước "
                        f"khi kết luận curve twist-secure.", value=twist_safety_bits)
        else:
            report.add("twist_security", "Twist security",
                        CheckStatus.PASS, f"#E_twist có ước lớn nhất tìm được ~"
                        f"{twist_safety_bits} bit (gần bằng {twist_order.bit_length()} bit "
                        f"của #E_twist) -> không phát hiện twist yếu trong ngưỡng trial division.",
                        value=twist_safety_bits)

    # --- Check #9: Hasse bound (sanity #E) ------------------------------------------
    t = p + 1 - E_count
    hasse_ok = (t * t <= 4 * p)
    report.add("hasse_bound_consistency", "Hasse: |#E-(p+1)| <= 2√p",
                CheckStatus.PASS if hasse_ok else CheckStatus.FAIL,
                (f"t=p+1-#E={t}, t²={t*t} <= 4p={4*p}: thoả Hasse." if hasse_ok else
                 f"t=p+1-#E={t} VI PHẠM Hasse (t²={t*t} > 4p={4*p}) -> #E (nguồn: "
                 f"{e_count_source}) SAI, hoặc n/h khai báo sai."),
                value={"t": t, "e_count_source": e_count_source})

    # --- Check bổ sung: tự kiểm #E bằng đếm trực tiếp (chỉ khi p đủ nhỏ) -----------
    if p <= brute_force_point_count_limit:
        counted = count_points_naive(curve)
        match = (counted == E_count)
        report.add("e_count_self_consistency", "#E tự kiểm bằng đếm trực tiếp (p nhỏ)",
                    CheckStatus.PASS if match else CheckStatus.FAIL,
                    (f"Đếm trực tiếp #E={counted}, khớp với giá trị dùng ở các check trên "
                     f"({e_count_source}={E_count})." if match else
                     f"LỆCH: đếm trực tiếp #E={counted} nhưng giá trị dùng ở trên "
                     f"({e_count_source})={E_count} -> n hoặc h khai báo SAI, hoặc #E truyền vào sai."),
                    value={"counted": counted, "used": E_count})
    else:
        report.add("e_count_self_consistency", "#E tự kiểm bằng đếm trực tiếp (p nhỏ)",
                    CheckStatus.INFO, f"Bỏ qua: p={p} > brute_force_point_count_limit="
                    f"{brute_force_point_count_limit:,} (không khả thi đếm trực tiếp).",
                    value=None)

    # --- Check #10: named/approved allow-list --------------------------------------
    registry = allow_list if allow_list is not None else CURVE_REGISTRY
    matched_name = None
    for name, ref in registry.items():
        if (p, a, b, G, n, h) == (ref.p, ref.a, ref.b, ref.G, ref.n, ref.h):
            matched_name = name
            break
    if matched_name:
        report.add("named_or_approved_allowlist", "Named/approved theo allow-list",
                    CheckStatus.PASS, f"Khớp CHÍNH XÁC tham số của curve đã đăng ký "
                    f"'{matched_name}' (vd NIST SP 800-186).", value=matched_name)
    else:
        report.add("named_or_approved_allowlist", "Named/approved theo allow-list",
                    CheckStatus.INFO, "Tham số KHÔNG khớp curve nào trong allow-list "
                    "-> đây là curve custom/toy; PHẢI tự đảm bảo mọi check khác ở trên "
                    "đều PASS trước khi dùng cho bất kỳ mục đích nào ngoài demo lab.",
                    value=None)

    return report


def _fmt_factors(factors: List[Tuple[int, int]]) -> str:
    if not factors:
        return "1"
    return "*".join(f"{p}^{e}" if e > 1 else f"{p}" for p, e in sorted(factors))


# ---------------------------------------------------------------------------
# 3. Self-test / demo (chạy: python -m validation.domain_checker)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("############################################################")
    print("# 1) Negative control: P-256 (kỳ vọng mọi check PASS/INFO)  #")
    print("############################################################")
    r1 = check_domain_parameters("P-256")
    r1.print_report()

    print("\n############################################################")
    print("# 2) Toy curve cofactor>1 (p=97,a=2,b=3,G=(0,10),n=50,h=2)  #")
    print("############################################################")
    toy_cof = {
        "curve_id": "crv-toy-cof2", "p": "97", "a": "2", "b": "3",
        "subgroup_n": "50", "cofactor_h": "2", "base_point_x": "0", "base_point_y": "10",
    }
    r2 = check_domain_parameters(toy_cof)
    r2.print_report()
    assert r2.get("cofactor_acceptable").status == CheckStatus.WARN
    assert r2.get("subgroup_order_primality").status == CheckStatus.FAIL  # n=50=2*5^2 smooth

    print("\n############################################################")
    print("# 3) Toy curve smooth n qua G=(3,6) (p=97,a=2,b=3,n=5,h=20) #")
    print("############################################################")
    toy_smooth = {
        "curve_id": "crv-toy-smooth", "p": "97", "a": "2", "b": "3",
        "subgroup_n": "5", "cofactor_h": "20", "base_point_x": "3", "base_point_y": "6",
    }
    r3 = check_domain_parameters(toy_smooth)
    r3.print_report()
    assert r3.get("subgroup_order_primality").status == CheckStatus.PASS  # n=5 nguyên tố
    assert r3.get("cofactor_acceptable").status == CheckStatus.FAIL       # h=20 quá lớn so với n

    print("\n############################################################")
    print("# 4) Curve BỊ LỖI cố ý: khai báo sai subgroup_n              #")
    print("############################################################")
    broken = dict(toy_cof)
    broken["curve_id"] = "crv-broken-n"
    broken["subgroup_n"] = "7"  # SAI: bậc thật của G=(0,10) trên curve này là 50, không phải 7
    r4 = check_domain_parameters(broken)
    r4.print_report()
    assert r4.overall_status == CheckStatus.FAIL
    assert r4.get("base_point_order_exact").status == CheckStatus.FAIL

    print("\n############################################################")
    print("# 5) Tìm & kiểm 1 curve ANOMALOUS nhỏ (#E == p)             #")
    print("############################################################")
    anomalous_curve = None
    for p_try in range(5, 200):
        if not is_probable_prime(p_try) or p_try <= 3:
            continue
        for a_try in range(p_try):
            for b_try in range(p_try):
                disc = (4 * a_try ** 3 + 27 * b_try ** 2) % p_try
                if disc == 0:
                    continue
                cnt = count_points_naive(
                    curve_from_d1_record({
                        "curve_id": "probe", "p": str(p_try), "a": str(a_try), "b": str(b_try),
                        "subgroup_n": "1", "cofactor_h": "1", "base_point_x": "0", "base_point_y": "0",
                    })
                )
                if cnt == p_try:
                    anomalous_curve = (p_try, a_try, b_try)
                    break
            if anomalous_curve:
                break
        if anomalous_curve:
            break

    if anomalous_curve:
        p_a, a_a, b_a = anomalous_curve
        # tìm 1 điểm bất kỳ khác O làm G (không cần đúng bậc cho demo này)
        g_point = None
        for x in range(p_a):
            rhs = (x ** 3 + a_a * x + b_a) % p_a
            for y in range(p_a):
                if (y * y - rhs) % p_a == 0:
                    g_point = (x, y)
                    break
            if g_point:
                break
        anomalous_record = {
            "curve_id": "crv-anomalous-demo", "p": str(p_a), "a": str(a_a), "b": str(b_a),
            "subgroup_n": str(p_a), "cofactor_h": "1",
            "base_point_x": str(g_point[0]), "base_point_y": str(g_point[1]),
        }
        print(f"Tìm thấy curve anomalous: p=a={p_a}, a={a_a}, b={b_a}")
        r5 = check_domain_parameters(anomalous_record)
        r5.print_report()
        assert r5.get("not_anomalous").status == CheckStatus.FAIL
    else:
        print("Không tìm thấy curve anomalous trong khoảng thử (bỏ qua demo #5).")

    print("\nSelf-test hoàn tất không lỗi (các assert đều pass).")