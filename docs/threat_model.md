# Threat Model — Topic 14: ECC Cryptanalysis & Implementation Failure Engineering

> **Trạng thái:** FINAL (gộp từ `threat_model_draft.md` cuối Tuần 1, bổ sung §A.9 Secure Storage) · **Phạm vi:** chỉ lab do nhóm kiểm soát (toy curve / container / regtest).
> **Nguồn:** Topic_14 guideline (mục 3–10, 13) · Cấu trúc đã chốt; các dòng `[TODO verify]` ở bảng CVE (§B.4) là việc xác minh nội dung đang chạy theo lịch Tuần 5–8 (`docs/project_plan.md`), không phải phần cấu trúc còn mở.

---

# PHẦN A — Task 1: Tài sản hệ thống & ranh giới tin cậy

## A.1 Chuỗi phân tích (theo guideline)

```
System → Asset/Key → Threat → Security Requirement → Curve/Algorithm
       → Implementation → Attack Evidence → Mitigation → Re-test
```

Mỗi dòng trong bảng bên dưới phải lần ngược/xuôi được theo chuỗi này.

## A.2 Hệ thống lab (system under study)

Bốn "bối cảnh" tối thiểu; nhóm chọn ≥1 (Cử nhân) hoặc ≥2 (Cao học):

| ID | Bối cảnh | Thành phần | Hàm mật mã chính |
|----|----------|-----------|------------------|
| S1 | JWT/OIDC lab (`system-demos/jwt-es256/`) | Signer (issuer), Verifier (resource server), JWKS endpoint | ECDSA P-256 (ES256) / Ed25519 |
| S2 | ECDH API (`system-demos/ecdh-api/`) | Service giữ static key, client gửi peer point | ECDH (Weierstrass toy) / X25519 |
| S3 | Blockchain regtest (`system-demos/blockchain-regtest/`) | Wallet signer, node regtest cục bộ | ECDSA secp256k1 |
| S4 | SSH/Git signing (tuỳ chọn) | Agent giữ key, repo/host | ECDSA P-256/P-521, Ed25519 |

## A.3 Kiểm kê tài sản (Asset Inventory)

Thang: **C**onfidentiality / **I**ntegrity / **A**vailability; mức tác động **H/M/L**.

| ID | Tài sản | Loại | Thuộc | Bảo vệ cần có | Tác động nếu lộ/hỏng | Ghi chú tấn công liên quan |
|----|---------|------|-------|----------------|----------------------|----------------------------|
| A1 | **Signing private scalar `d_sign`** | Bí mật dài hạn | S1,S3,S4 | C, I | **H** — giả mạo token/giao dịch/commit | Nonce reuse/bias, timing, fault, **lưu trữ khóa plaintext (§A.9)** |
| A2 | **ECDH static private scalar `d_dh`** | Bí mật dài hạn | S2 | C | **H** — giải mã lưu lượng, mạo danh | Invalid-curve, small-subgroup, **lưu trữ khóa plaintext (§A.9)** |
| A3 | **Per-signature nonce `k`** | Bí mật tạm thời (1 lần) | S1,S3,S4 | C (tuyệt đối), unpredictability | **H** — 1 `k` lộ ⇒ lộ `d` | Reuse, bias, partial leak |
| A4 | Ephemeral ECDH scalar | Bí mật tạm thời | S2 | C | M | Chỉ nguy hiểm nếu tái dùng/dự đoán được |
| A5 | **Domain parameters** (`p,a,b,G,n,h`) | Tham số công khai nhưng toàn vẹn quan trọng | Tất cả | **I** | **H** — tham số yếu ⇒ ECDLP yếu | Singular/anomalous/smooth order |
| A6 | Public key / JWK / certificate | Công khai, cần xác thực | S1,S2,S3 | I | H — thay key ⇒ verifier chấp nhận kẻ tấn công | Wrong-curve JWK, key confusion |
| A7 | Peer public point (đầu vào ECDH) | Dữ liệu **không tin cậy** | S2 | Validation | H — nguồn của invalid-curve | Điểm ngoài curve/subgroup |
| A8 | Signature / token / tx (đầu vào verifier) | Dữ liệu **không tin cậy** | S1,S3 | Validation (canonical) | H — verifier bypass | Non-canonical S ≥ L, malleability |
| A9 | Shared secret & KDF output | Bí mật phiên | S2 | C | H | All-zero secret (X25519) |
| A10 | RNG / entropy source / deterministic-nonce code (RFC 6979) | Thành phần tin cậy | S1,S3,S4 | Integrity + quality | **H** — gốc của nonce failure | Boot-time entropy, RNG bias |
| A11 | Key lifecycle metadata (kid, rotation, revocation list) | Cấu hình | S1,S3 | I, A | M–H | Stale/reused key sau rotation |
| A12 | Error messages / response behavior / timing của API | **Kênh thông tin ngầm** | S2,S1 | Uniformity | M–H — trở thành *oracle* | Decryption feedback (cf. CVE-2019-9155) |
| A13 | Test corpora D1–D7, raw timing/trace | Dữ liệu nghiên cứu | Repo | I, tái lập | L–M | Không chứa secret production |
| A14 | Build & dependency (library + version, container image) | Chuỗi cung ứng | Tất cả | I | M — sai version ⇒ kết luận sai CVE | Pin commit/version bắt buộc |

> **Nguyên tắc:** A1–A3 là "crown jewels". A7, A8, A12 không phải bí mật nhưng là **bề mặt tấn công** — đây là chỗ work factor bị phá.

## A.4 Ranh giới tin cậy (Trust Boundaries)

```
 ┌───────────────────────────── TB0: Lab host / ranh giới nghiên cứu ───────────────────────────┐
 │                                                                                              │
 │  [Attacker harness]                                                                          │
 │   (mô phỏng ngoài tin cậy)                                                                   │
 │        │  A7 peer point / A8 token / tx / sig           (dữ liệu KHÔNG tin cậy)              │
 │ ═══════╪════════════════ TB1: Network/API boundary ═══════════════════════════════════════   │
 │        ▼                                                                                     │
 │   ┌──────────────────────────────┐   TB2: Parser/Validation boundary                         │
 │   │ Parser / decoder / validator │ ── on-curve? subgroup? canonical? alg pinned? ──┐         │
 │   └──────────────────────────────┘                                                 ▼         │
 │ ═══════════════════ TB3: Crypto-core boundary (library) ═══════════════════════════          │
 │   ┌──────────────────────────────┐        ┌──────────────────────────┐                       │
 │   │ Scalar mult / sign / verify  │◄──────►│ RNG / RFC 6979 nonce gen │  TB4: Entropy boundary│
 │   └──────────────┬───────────────┘        └──────────────────────────┘                       │
 │ ═══════════════════╪═══ TB5: Key-storage boundary (process memory / agent / HSM-sim) ═══════  │
 │   ┌───────────────▼──────────────┐                                                           │
 │   │  d_sign, d_dh (A1, A2)       │                                                           │
 │   └──────────────────────────────┘                                                           │
 │ ═══ TB6: Physical/microarchitectural (CPU cache, timing, power) — chỉ tồn tại ở track F ═══   │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
        TB7: Supply-chain boundary (dependency versions / patches) bao quanh TB3
```

| TB | Ranh giới | Phía "không tin cậy" → "tin cậy" | Kiểm soát bắt buộc | Thất bại tiêu biểu | Track |
|----|-----------|----------------------------------|--------------------|--------------------|-------|
| TB1 | Network/API | Client/peer → service | Rate-limit, auth, uniform error | Oracle lặp lại không giới hạn | D |
| TB2 | **Parser / validation** | Bytes → đối tượng điểm/chữ ký | Not-infinity, coord range, on-curve, subgroup (nếu `h>1`/twist), canonical encoding, alg/curve pinning | **Invalid-curve, verifier bypass** | D, G |
| TB3 | Crypto core | Đối tượng đã validate → phép toán | Constant-time, blinding, kiểm tra kết quả (fault) | Timing/cache/fault leak | F |
| TB4 | Entropy | RNG → nonce | CSPRNG hoặc RFC 6979; không tự chế | Reuse, bias, low entropy | C, E |
| TB5 | Key storage | Process/OS khác → scalar | Cô lập process, agent/HSM, quyền file | Key bị đọc, 1 key ủy quyền nhiều host | C, D (§A.9) |
| TB6 | Vật lý / vi kiến trúc | Co-tenant/đo đạc → CPU | Pin CPU, noise, constant-time | Cache/power leakage | F (tuỳ chọn) |
| TB7 | Supply chain | Upstream → build | Pin version/commit, ghi ngày truy xuất | Dùng bản vá/chưa vá sai | CVE corpus |

**Điểm mấu chốt:** TB2 là ranh giới mà guideline nhấn mạnh — *point/subgroup validation thuộc về yêu cầu mật mã, không chỉ là input sanitation.* Giả định "dữ liệu qua TB2 đã sạch" là nguồn của CVE-2015-7940, CVE-2016-9121, CVE-2026-26007.

## A.5 Mô hình kẻ tấn công

| Mã | Năng lực | Quan sát được | Bị cấm/ngoài phạm vi |
|----|----------|---------------|---------------------|
| ATK-1 Remote, passive | Quan sát chữ ký/token công khai | Nhiều `(r,s,H(m))` | Truy cập key |
| ATK-2 Remote, active (oracle) | Gửi điểm/chữ ký tuỳ ý, thấy phản hồi | Accept/reject, lỗi, độ trễ | Tấn công target ngoài lab |
| ATK-3 Local co-tenant | Đo cycles/timing cùng máy | Phân phối thời gian | Phá hạ tầng thật |
| ATK-4 Physical (tuỳ chọn) | Trace năng lượng/EM trên MCU sở hữu | Traces | Phần cứng không thuộc nhóm |
| ATK-5 Supply-chain | Dùng version dính CVE | — | Công bố exploit chưa vá |

**Giả định:** attacker biết domain parameters, thuật toán, mã nguồn (Kerckhoffs); không có sẵn `d`, `k`.

## A.6 Phân tích mối đe doạ theo tài sản (STRIDE rút gọn)

| Tài sản | Threat | Loại | Yêu cầu bảo mật | Biện pháp |
|---------|--------|------|-----------------|-----------|
| A1 | Khôi phục `d` từ chữ ký (nonce) | Information disclosure | Nonce duy nhất & không đoán được | RFC 6979 / CSPRNG; detector `repeated_r` |
| A1 | Rò timing khi ký | Information disclosure | Constant-time | Constant-time + blinding |
| A2 | Rò `d_dh mod r` qua invalid point | Information disclosure | Validate peer point | On-curve + subgroup; uniform error |
| A5 | Tham số yếu/tuỳ chỉnh | Tampering | Dùng named curve | Allow-list curve; kiểm tra Δ≠0, factor `#E` |
| A6 | JWK sai curve/alg | Spoofing | Pin alg + curve | Allow-list `alg`, `crv`, `kid` |
| A8 | Chữ ký non-canonical được chấp nhận | Spoofing/Repudiation | Canonical verify | Reject `S ≥ L` (Ed25519), low-S (secp256k1) |
| A12 | Phản hồi khác biệt = oracle | Information disclosure | Uniform response | Một mã lỗi, thời gian ổn định |
| A14 | Version dính CVE | Elevation of privilege | Pin & verify | SBOM, ghi `affected/fixed` |

## A.7 Ngoài phạm vi (Out of scope)

- Tuyên bố *phá* P-256, secp256k1, Ed25519 ở kích thước đầy đủ (chúng chỉ là **negative control**).
- Mọi key/credential production; tấn công public blockchain; target không thuộc nhóm.
- Tấn công lượng tử (Shor) — ghi chú ngoài đề tài.

## A.8 Câu hỏi mở `[TODO]`

1. Nhóm chọn S1–S4 nào? Track nào (A–G)? → **Đã chốt: S1 (JWT) + S2 (ECDH API), Track A+C+D.**
2. ~~Có dùng HSM-giả lập/agent tách process để có TB5 thật không?~~ → **Đã chốt (xem A.9):**
   không dựng S4/HSM riêng; thay vào đó TB5 được kiểm thử **tối giản** ngay
   trong System Demo 1 & 2 bằng `signatures/key_storage.py`.
3. Danh sách CVE tối thiểu (≥4 Cử nhân / ≥6 Cao học) đã chốt `affected/fixed`?

## A.9 Bổ sung — Secure Storage (TB5), tích hợp tối giản vào Track C/D

**Lý do bổ sung:** đồ án được yêu cầu nhìn từ 3 góc độ ngang hàng — *Secure
Communication*, *Secure Storage*, *Secure Process Logic*. Track C (JWT) và
Track D (ECDH) vốn đã phủ tốt 2 góc đầu (giao thức trao đổi khóa/xác thực =
Communication; bỏ qua logic phân quyền của verifier, thiếu bước validate
trong luồng xử lý ECDH = Process Logic), nhưng **Secure Storage** trước đó
chỉ dừng ở việc liệt kê TB5 trong bảng trust boundary, không có thực nghiệm
nào đi hết chuỗi vulnerable→evidence→mitigation→re-test cho nó.

**Phạm vi tối thiểu (không dựng track/demo mới):**
- `d_sign` (A1) và `d_dh` (A2) — thay vì chỉ tồn tại dưới dạng biến Python
  lúc chạy — được **ghi ra đĩa** theo 2 chế độ, dùng chung 1 module
  `signatures/key_storage.py`:
  - **Chế độ dễ tổn thương:** file JSON plaintext, quyền mặc định của hệ
    điều hành (không siết `chmod`).
  - **Chế độ đã vá:** mã hoá tại chỗ (khóa dẫn xuất từ passphrase qua KDF,
    passphrase KHÔNG lưu cùng file) + quyền file `0600`.
- Mỗi `app.py`/`patched_app.py` (cả JWT và ECDH demo) nạp khóa qua
  `key_storage.py` thay vì sinh khóa tạm trong RAM.
- Bước re-test đã có sẵn (`test_retest.ipynb` của cả 2 demo) có thêm 1 bước:
  thử **đọc trực tiếp file khóa từ đĩa** — không cần ECDLP, không cần nonce
  reuse, chỉ cần quyền đọc file — ghi nhận `key_extracted` (True/False) vào
  `data/D6_timing.csv`.

**Điểm sư phạm quan trọng cần nêu trong báo cáo:** đây là bằng chứng cho
thấy 3 góc nhìn **độc lập với nhau** — một signer đã vá hoàn toàn nonce reuse
(RFC 6979) vẫn có thể bị phá hoàn toàn chỉ vì lưu khóa sai cách, chứng minh
"Secure Communication" không suy ra "Secure Storage".

Chi tiết thiết kế: `docs/experimental_design.md` mục mới (sau Track D).

---

# PHẦN B — Task 3: Các tầng sụp đổ không gian tìm kiếm

## B.1 Khung định lượng

Điểm khởi đầu: tìm `d` trong `Q = dG`, `G` bậc nguyên tố `n`. "Brute force" không phải baseline thực tế — baseline là thuật toán generic.

```
W_brute ≈ n                       (kỳ vọng ~ n/2 phép thử)
W_BSGS  ≈ O(√n) thời gian + O(√n) bộ nhớ
W_rho   ≈ O(√n) thời gian, bộ nhớ ~ không đáng kể   (≈ √(πn/2) phép cộng điểm)

W_eff = min{ W_ECDLP, W_curve, W_nonce, W_oracle, W_sidechannel, W_fault, W_verifier }
```

Với `n ≈ 2^256`: `W_rho ≈ 2^128` (không phải `2^256`). `W_eff` là **mắt xích yếu nhất** của cả hệ thống, không phải độ khó ECDLP.

## B.2 Thang các tầng sụp đổ

| # | Tầng | Cơ chế làm giảm work | Điều kiện tiên quyết | Work trước → sau | Tác động | Track |
|---|------|---------------------|----------------------|------------------|----------|-------|
| L0 | **Generic ECDLP** | Pollard rho / BSGS thay quét `n` | Không (luôn đúng) | `O(n)` → `O(√n)` | Định nghĩa ngưỡng "an toàn" (128-bit cho 256-bit) | A |
| L1 | **Unsafe curve/order** | Smooth order → Pohlig–Hellman; anomalous → Smart; low embedding degree → MOV/Frey–Rück; singular → nhóm đơn giản | Tham số do attacker/legacy/tự chế chọn | `O(√n)` → `O(√q_max)` (PH) hoặc đa thức (anomalous/singular) | Phá ECDLP *cấp tham số* | B |
| L2 | **Invalid-curve / small-subgroup** | Điểm bậc nhỏ `r_i` + oracle ⇒ `d mod r_i`; CRT ghép | Thiếu validate TB2 + có oracle | `O(√n)` → `Σ O(√r_i)` + CRT; số query ≈ số điểm dùng (value oracle) hoặc ≈ `Σ r_i` (accept/reject oracle) | Lộ `d_dh` từng phần → toàn bộ | D |
| L3 | **ECDSA nonce reuse** | 2 chữ ký chung `r` ⇒ giải tuyến tính | `repeated_r` | `O(√n)` → `O(1)` (vài phép nghịch đảo mod n) | Lộ `d_sign` ngay | C |
| L4 | **Predictable/low-entropy nonce** | Liệt kê ứng viên `k` | RNG yếu | `O(√n)` → `2^{entropy(k)}` | Lộ `d_sign` | C |
| L5 | **Biased / partial nonce (HNP)** | Mỗi chữ ký rò vài bit ⇒ lattice (LLL/BKZ) gom bằng chứng | ~`m` chữ ký, bias/leak ≥ ngưỡng | `O(√n)` → đa thức theo `m`, dim lattice | PuTTY P-521: ~60 chữ ký ⇒ khôi phục key (CVE-2024-31497) | E |
| L6 | **Timing/cache/power** | Rò bit/độ dài nonce hoặc scalar ⇒ thu hẹp ứng viên, cấp mẫu cho HNP | Đo đạc (local/remote) | Giảm entropy `k` còn `n/2^{leak}` | OpenSSL CVE-2024-13176 (timing, nonce inversion) | F |
| L7 | **Fault** | Điểm/chữ ký lỗi cho quan hệ đại số | Gây lỗi được | ECDLP → phân biệt đại số | Lộ secret-dependent relation | (MSc) |
| L8 | **Verifier bug** | Chấp nhận đối tượng malformed/non-canonical | Parser/verifier đặc tả chưa đủ | `O(√n)` → **bỏ hẳn việc tìm key** (dựng object được chấp nhận) | CVE-2026-33895 (node-forge Ed25519 `S ≥ L`) | G |

> **Phân biệt quan trọng (guideline):** L1 ≠ L2. L1 là chọn *domain parameters* yếu; L2 là *lỗi validation* trên curve chuẩn mạnh. Curve chuẩn không yếu đi khi library validate sai.

## B.3 Chi tiết toán học từng tầng

### L0 — Generic
- Exhaustive: thử `d = 1..n`; kỳ vọng `n/2` phép nhân/cộng điểm.
- BSGS: `m = ⌈√n⌉`; bảng `jG` (baby), giant steps `Q − imG`; thời gian & bộ nhớ `O(√n)`.
- Rho: bước đi giả ngẫu nhiên, phát hiện va chạm (Floyd/distinguished points); song song hoá tốt.
- **Thí nghiệm A:** vẽ `log(ops)` theo `log(n)`, hệ số góc kỳ vọng ≈ **0.5** (rho/BSGS) vs **1.0** (exhaustive).

### L1 — Unsafe order (Pohlig–Hellman)
Nếu `n = ∏ q_i^{e_i}`: giải `d mod q_i^{e_i}` rồi CRT.
```
W_PH ≈ Σ e_i · ( log n + √q_i )   ⇒  bị chi phối bởi  q_max = largest prime factor
```
- Báo cáo bắt buộc: `factor(#⟨G⟩)`, `q_max`, `W_eff ≈ √q_max`.
- Anomalous (`#E(F_p) = p`): Smart attack ⇒ thời gian đa thức. Chỉ minh hoạ toy.
- Embedding degree nhỏ: MOV/Frey–Rück chuyển ECDLP sang DLP trên `F_{p^k}`.
- Singular (`Δ = 4a³+27b² = 0`): không phải nhóm elliptic.

### L2 — Invalid-curve / small-subgroup
Công thức cộng/nhân Weierstrass không dùng `b` ⇒ điểm `P' ∈ E'(b')` bị xử lý mà không bị phát hiện. Chọn `E'` có nhóm con bậc nhỏ `r_i`:
```
P_i bậc r_i  ──oracle──►  d mod r_i  ──CRT──►  d mod (∏ r_i)
Query ≈ #điểm (value oracle, so khớp offline) hoặc ≈ Σ r_i (accept/reject oracle)  |  Khi ∏ r_i ≥ n  ⇒ khôi phục toàn bộ d
```
Với `h > 1` (Curve25519 `h=8`, toy `h>1`): small-subgroup đưa `d mod h`, cần cofactor clearing/kiểm tra.

### L3 — Nonce reuse (đại số, không phải ECDLP)
```
s_i = k^{-1}(H_i + d·r) mod n      (cùng k ⇒ cùng r)
k = (H1 − H2)(s1 − s2)^{-1} mod n
d = (s1·k − H1)·r^{-1} mod n
```
Detector corpus D3: trường `repeated_r`.

### L5 — Biased nonce → HNP
Mỗi chữ ký cho `t_i + u_i·d ≡ k_i (mod n)` với `k_i` nhỏ (bias/leak ℓ bit). Ước lượng số mẫu `m ≳ log₂(n)/ℓ` (thô); dựng lattice dim `m+1`, giải SVP/CVP bằng LLL/BKZ (fpylll/Sage). Báo cáo: `leak model, #signatures, lattice dimension, success probability, runtime`.

### L6–L7 — Side-channel & fault
- Đo cycles trên CPU pin, warm-up, nhiều lần; so sánh bản dễ tổn thương vs constant-time; kiểm định thống kê (phân phối, tách biệt lớp).
- Kết quả âm (không phát hiện được) vẫn là bằng chứng hợp lệ.

### L8 — Verifier
Không tìm `d`; dựng đối tượng được chấp nhận. Đo bằng **accepted/rejected matrix** giữa bản lỗi/bản vá/thư viện tham chiếu (corpus D5).

## B.4 Bảng ánh xạ tầng → CVE → bằng chứng

| Tầng | CVE/case | Phiên bản (theo guideline) | Precondition | Bằng chứng cần thu | Mitigation |
|------|----------|----------------------------|--------------|--------------------|------------|
| L2 | CVE-2015-7940 Bouncy Castle | `[TODO verify]` | Remote ECDH, điểm không kiểm on-curve | #query, `d mod r_i`, candidate space | On-curve + subgroup check |
| L2 | CVE-2016-9121 go-jose ECDH-ES | `[TODO verify]` | JWE ECDH-ES, không check cùng curve | Oracle qua xử lý JWE | Check same-curve |
| L2/oracle | CVE-2019-9155 OpenPGP.js | `[TODO verify]` | Forged msg + decryption feedback | Feedback = oracle | Validate + uniform error |
| L2 | CVE-2026-26007 pyca/cryptography | fixed **46.0.5** (theo guideline) | SECT curves, thiếu prime-order subgroup check | ECDH rò residue; ECDSA forge ở subgroup nhỏ | Nâng cấp, subgroup validation |
| L5 | CVE-2024-31497 PuTTY | `[TODO verify]` | P-521, nonce bias | ~60 chữ ký ⇒ key | RFC 6979 |
| L5 | CVE-2024-1544 wolfSSL | `[TODO verify]` | Control-flow-revealing nonce bias | Bias + lattice | Constant-time nonce generation |
| L6 | CVE-2024-13176 OpenSSL | `[TODO verify]` | Timing trong nonce inversion; mạnh nhất với P-521, đo local | Phân phối cycles | Bản vá + constant-time |
| L8 | CVE-2026-33895 node-forge | `[TODO verify]` | Ed25519 `S ≥ L` | Matrix accept/reject | Reject non-canonical |

> Phân biệt **claim của CNA/NVD** và **suy luận của sinh viên** (corpus D7).

## B.5 Mô hình tổng hợp & lập luận bảo mật

Cho mỗi track, nhóm phải nêu:
1. `W_eff` **trước** (vulnerable baseline) — số đo thực nghiệm.
2. `W_eff` **sau** mitigation — chạy *cùng test* (identical re-test).
3. Giả định còn lại (residual assumptions): ví dụ vá nonce nhưng còn timing; validate nhưng còn oracle thời gian.

| Metric | Đơn vị | Dùng cho tầng |
|--------|--------|---------------|
| Candidate-space size, group ops | bit / số phép | L0, L1 |
| Oracle queries | số | L2 |
| #signatures | số | L3–L5 |
| CPU cycles, traces | cycles / số | L6–L7 |
| Accepted/rejected | ma trận | L8 |
| Recovery time, success prob. | s, % | tất cả |

**Negative controls:** curve đầy đủ + library đã vá phải chống được tấn công đã chọn; báo cáo kết quả âm, không ép thành công.

## B.6 Checklist liên kết
- [ ] Brute force ≠ generic ECDLP ≠ implementation collapse (L0 vs L1–L8) đã phân biệt rõ.
- [ ] Mỗi tầng được chọn có vulnerable baseline, evidence, mitigation, re-test.
- [ ] Không tuyên bố phá standard curve từ toy experiment.
