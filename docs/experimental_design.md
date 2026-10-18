# Experimental Design — Track A, C, D (Topic 14)

> **Trạng thái:** DRAFT v0.1 · **Liên kết:** `docs/threat_model_draft.md` (tầng L0, L3, L2) · `curves/math_notes.md` · `docs/references.md`
> **Phạm vi an toàn:** toàn bộ target là code/toy curve/container do nhóm kiểm soát; khoá là **disposable lab key**; không dùng production key, không tấn công public chain.
> Mọi thí nghiệm theo vòng: **vulnerable baseline → evidence → mitigation → identical re-test** (checklist mục 17 của đề).

---

## 0. Tổng quan ba track

| | **A — Generic search baseline** | **C — ECDSA nonce reuse** | **D — Invalid-curve / small-subgroup** |
|---|---|---|---|
| Tầng work-factor | L0: `O(n)` → `O(√n)` | L3: `O(√n)` → `O(1)` (đại số) | L2: `O(√n)` → `Σ O(√rᵢ)` + CRT |
| Câu hỏi nghiên cứu | Slope thực nghiệm của exhaustive/BSGS/rho có khớp 1.0 / 0.5 không? | Cần bao nhiêu chữ ký để lộ khoá khi `k` tái dùng? Mitigation chặn được gì? | Mỗi query lộ bao nhiêu bit của `d`? Validation chặn ở đâu? |
| Đối tượng | Toy group nguyên tố (16–48 bit) | JWT ES256 signer/verifier lab (P-256, key dùng 1 lần) | Toy ECDH API (Weierstrass, `n` ≤ 40 bit) |
| Corpus | D1, D2 | D3 (+ D5 phụ) | D1, D4 |
| Mức | Cử nhân | Cử nhân | Cử nhân/Cao học |
| Tuần (theo plan) | 3 | 5–6 | 7 |
| Negative control | P-256/secp256k1/Ed25519: chỉ metadata + ngoại suy | Signer đã vá RFC 6979 | Validator đầy đủ + curve chuẩn |

Phụ thuộc: **A → C, D** chỉ ở mức công cụ chung (số học điểm, ghi log CSV). C và D độc lập nhau.

---

## 1. Khung chung (áp dụng cho cả A, C, D)

### 1.1 Môi trường tái lập
| Hạng mục | Quy định |
|----------|----------|
| Ngôn ngữ | Python ≥ 3.11 (prototype); C tuỳ chọn cho vòng lặp nóng (Track A, đo cycles) |
| Thư viện | `gmpy2`, `sympy`, `numpy`, `pandas`, `matplotlib`; `cryptography` (**pin version**, làm verifier tham chiếu độc lập); Sage/PARI (`ellcard`) cho đếm điểm toy |
| Container | `Dockerfile` pin base image digest + `requirements.lock`; ghi `git commit` vào mỗi file kết quả |
| Seed | Mọi trial có `seed` (ghi vào CSV); dùng `numpy.random.Generator(PCG64(seed))`; khoá lab sinh từ seed ⇒ tái tạo được thay vì lưu |
| Máy đo | Ghi CPU model, OS, kernel, Python/gmpy2 version; pin CPU (`taskset`) khi đo thời gian; warm-up 3 vòng bỏ |
| Đếm phép toán | Bộ đếm `op_counter` trong lớp `Curve.add/double` — **đơn vị chính là group operations**, không phụ thuộc máy |

### 1.2 Cấu trúc thư mục
```
curves/          # gen_toy_curve.py, ecc.py (add/mul), algos/{exhaustive,bsgs,rho}.py
signatures/      # ecdsa_lab.py (signer có/không lỗi), nonce_corpus.py, recover.py, detector.py
validation/      # point_fixtures.py, validators.py
system-demos/
  jwt-es256/     # signer/, verifier/, jwks/, tests/
  ecdh-api/      # service_vuln.py, service_patched.py, attacker_toy.py
data/            # D1..D4 *.csv (không chứa secret production)
scripts/         # run_trackA.sh, run_trackC.sh, run_trackD.sh, plot_*.py, make_report_tables.py
docs/            # experimental_design.md, runbook, ethics/disclosure
```

### 1.3 Giao thức một thí nghiệm (6 bước)
```
 [1] Pre-register: giả thuyết H, tham số, tiêu chí chấp nhận (mục *.2 mỗi track) → commit trước khi chạy
 [2] Sinh fixture (toy/lab key) từ seed          → data/*.csv  (D1/D3/D4)
 [3] Chạy VULNERABLE baseline N trial            → results/<track>/vuln_*.csv
 [4] Phân tích: metric, CI, plot                 → figures/
 [5] Áp mitigation (chỉ đổi phần bị lỗi)         → tag git `patched-*`
 [6] Chạy IDENTICAL re-test (cùng seed, script, tham số) → results/<track>/patched_*.csv
     → so sánh before/after; ghi residual assumptions
```
**Quy tắc "identical":** chỉ một biến thay đổi giữa [3] và [6] (bản signer/validator). Hash của script test được ghi vào kết quả.

### 1.4 Thống kê dùng chung
- Báo cáo **median, IQR, min–max**; CI 95% bằng **bootstrap** (≥ 2000 lần lấy mẫu lại).
- Hồi quy `log₂(y) = α·log₂(x) + β` bằng OLS, báo `α` ± CI.
- Cử nhân: median/query counts + reproducible. Cao học (mở rộng): phân phối đầy đủ, CI, ablation.
- Báo cáo kết quả âm nguyên trạng; **không tinh chỉnh tham số để ép thành công**.

### 1.5 Guardrail an toàn (bắt buộc trong code)
| Guardrail | Cách thực thi |
|-----------|----------------|
| Không tấn công ngoài lab | Attacker harness chỉ nói chuyện với `localhost`/container network nội bộ |
| Giới hạn kích thước toy | `assert n_bits <= 48` trong mọi script phá ECDLP/oracle; từ chối curve có `n_bits` lớn hoặc curve chuẩn |
| Disposable key | Khoá lab sinh từ seed, có tiền tố `LAB-`; script từ chối nạp key không có tiền tố |
| Không lưu secret thật | `.gitignore` + pre-commit hook quét PEM/WIF/private-key pattern |
| Responsible-use note | `docs/ethics.md`: phạm vi, quy trình disclosure nếu phát hiện lỗi thư viện ngoài ý muốn |

---

# TRACK A — Generic Search Baseline (Exhaustive vs BSGS vs Pollard rho)

## A.1 Mục tiêu & giả thuyết

| ID | Giả thuyết | Kiểm chứng bằng |
|----|-----------|------------------|
| HA1 | Exhaustive: số group ops kỳ vọng ≈ `n/2` ⇒ hệ số góc `α ≈ 1.0` | hồi quy `log₂ ops` ~ `log₂ n` |
| HA2 | BSGS: ops ≈ `O(√n)` (≈ `m + n/m`, `m=⌈√n⌉`), bộ nhớ ≈ `√n` ⇒ `α_time ≈ 0.5`, `α_mem ≈ 0.5` | hồi quy ops, peak memory |
| HA3 | Pollard rho: ops ≈ `c·√n` với `c` gần `√(π/2) ≈ 1.25`, `α ≈ 0.5`, bộ nhớ ≈ hằng | hồi quy + tỷ lệ `ops/√n` |
| HA4 | Với cùng `n`, rho/BSGS nhanh hơn exhaustive; điểm giao cắt xuất hiện ở `n` nhỏ | so sánh `ops` theo `n_bits` |

**Thông điệp cần chứng minh:** brute-force `O(n)` không phải baseline thực tế; thiết kế 256-bit tương ứng ≈ 128-bit generic work.

## A.2 Tiêu chí chấp nhận (đặt trước khi chạy)
- Hồi quy exhaustive: `α ∈ [0.9, 1.1]`; BSGS & rho: `α ∈ [0.4, 0.6]` (CI 95% giao với khoảng này).
- `recovered == True` ở 100% trial không bị timeout; mọi `d` tìm được thoả `d·G == Q` (tự kiểm).
- Tỷ lệ `median(ops_rho)/√n` nằm trong `[1.0, 2.0]` (hằng số phụ thuộc cách chọn walk/DP; ghi rõ).
- Nếu không đạt: báo cáo trung thực và phân tích nguyên nhân (walk thiên lệch, DP quá thưa…).

## A.3 Biến thí nghiệm

| Biến | Giá trị | Ghi chú |
|------|---------|---------|
| Thuật toán | `exhaustive`, `bsgs`, `rho` | |
| `n_bits` (bit của subgroup order) | exhaustive: 16,18,…,**26**; bsgs: 16,20,…,**40**; rho: 16,20,…,**48** | Trần do giới hạn thời gian/bộ nhớ Python; điều chỉnh sau pilot |
| Số trial/điểm | 30 (≤ 32 bit), 15 (> 32 bit) | `d` ngẫu nhiên đều trong `[1, n−1]` |
| Curve | Toy prime-order (`h = 1`), sinh mới cho mỗi `n_bits` | Xem A.4 |
| Timeout/trial | 10 phút | Ghi `timeout=True`, không bỏ trial |
| rho | `r = 20` nhánh walk (additive), DP mask ≈ `log₂(√n)/2` bit; 1 luồng (song song = mở rộng) | Ghi tham số vào CSV |

Pilot (bắt buộc): chạy 5 trial/điểm để ước lượng thời gian rồi mới chốt trần `n_bits`.

## A.4 Sinh toy group (Corpus D1)
```
for n_bits in sizes:
    repeat:
        chọn p nguyên tố ≈ n_bits bit; chọn (a,b) ngẫu nhiên
        loại nếu Δ = 4a³+27b² ≡ 0
        #E ← ellcard (Sage/PARI)            # đếm điểm
        chấp nhận nếu #E nguyên tố (h = 1) và #E ≠ p (không anomalous)
                    và embedding degree k > ngưỡng (n ∤ p^i−1, i ≤ 20)
        G ← điểm ngẫu nhiên ≠ O (bậc n = #E)
    ghi D1: curve_id,p,a,b,discriminant_ok,#E,subgroup_n,cofactor_h(=1),largest_prime_factor(=n),category=safe_toy
```
Tự kiểm: `Hasse` thoả; `n·G = O`.

## A.5 Luồng thực thi
```
 gen_toy_curve.py ──► D1.csv
        │
        ▼
 for algo in {exhaustive,bsgs,rho}; for n_bits; for trial in 1..T:
      seed = f(algo,n_bits,trial)   # cố định → tái lập
      d ← rand(1..n−1);  Q ← d·G
      reset op_counter; start timers (perf_counter_ns; cycles nếu có bản C)
      d' ← algo(G,Q,n)
      stop; assert d'·G == Q
      append D2 row
        │
        ▼
 analyze_A.py: median/IQR, bootstrap CI, OLS slope, plots
```

### Chi tiết thuật toán
- **Exhaustive:** `R ← O; for j=1..n: R ← R+G; if R==Q → d=j`. Đếm 1 add/vòng.
- **BSGS:** `m=⌈√n⌉`; bảng `{jG : j<m}` (lưu `x` + dấu); giant step `Q − i·(mG)`; tra bảng; `d = i·m + j`. Ghi `memory_entries = m`.
- **Rho:** walk `R_{i+1} = R_i + M_s(R_i)` theo hàm phân hoạch `s` trên toạ độ `x`; mỗi điểm giữ `(a,b)` với `R = aG + bQ`; lưu **distinguished points**; va chạm ⇒ giải `d = (a₁−a₂)/(b₂−b₁) mod n`; nếu `b₂ ≡ b₁` thì khởi động lại với điểm đầu mới (đếm số lần restart).

## A.6 Dữ liệu thu (Corpus D2 — schema)
```
curve_id, algorithm, n_bits, trial, seed, operations, restarts, cpu_cycles,
wall_time_ns, memory_peak_kib, memory_entries, recovered, timeout, params_json,
git_commit, host_id
```
- `operations` = tổng add+double của **thuật toán** (không tính chi phí setup `Q=dG`).
- `cpu_cycles`: bản C với `rdtsc`; bản Python ghi `NA`.

## A.7 Phân tích & hình
| Hình | Nội dung |
|------|----------|
| FA1 | log–log `ops` vs `n` cho 3 thuật toán + đường chuẩn slope 1.0 và 0.5 |
| FA2 | Phân phối `ops/√n` của rho (boxplot theo `n_bits`) + đường `1.25` |
| FA3 | Bộ nhớ BSGS vs rho theo `n` |
| FA4 | Điểm giao cắt thời gian (wall-time) của exhaustive vs rho/BSGS |

## A.8 Ngoại suy & negative control (chỉ lý thuyết, **không chạy**)
- Từ tốc độ đo được `ops/giây` (v), ngoại suy thời gian cho `n ≈ 2^256`: `T ≈ c·2^128 / v` — ghi rõ đây là **ước lượng quy mô**, không phải thí nghiệm.
- Corpus D2 chỉ chứa **metadata** cho P-256/secp256k1/Ed25519 (`recovered = NA`). **Cấm** tuyên bố phá curve chuẩn.

## A.9 Rủi ro & xử lý
| Rủi ro | Xử lý |
|--------|-------|
| Rho phương sai lớn (đuôi nặng) | Tăng trial; báo median/IQR; dùng timeout + ghi nhận |
| Walk lặp chu kỳ ngắn / `b₁≡b₂` | Restart với điểm đầu mới; ghi `restarts` |
| Python chậm ở `n` lớn | Hạ trần `n_bits` hoặc chuyển vòng lặp nóng sang C |
| BSGS tràn RAM | Giới hạn `n_bits ≤ 40`; ghi `memory_peak` |

## A.10 Đầu ra Track A
`data/D1.csv`, `data/D2.csv`, FA1–FA4, `results/trackA/summary.md` (bảng slope ± CI, kết luận HA1–HA4).

---

# TRACK C — ECDSA Nonce Reuse (JWT ES256 Lab)

## C.1 Mục tiêu & giả thuyết

| ID | Giả thuyết | Kiểm chứng |
|----|-----------|------------|
| HC1 | Hai chữ ký cùng `k`, khác thông điệp ⇒ phục hồi `d` trong thời gian ~ vài phép nghịch đảo mod `n` (không liên quan ECDLP) | Recovery 100% khi có cặp hợp lệ |
| HC2 | Khi chỉ một tỷ lệ chữ ký tái dùng `k`, số chữ ký cần đến lần lặp `r` đầu tiên phụ thuộc cơ chế lỗi | Đo `sigs_to_first_repeat` |
| HC3 | Sau phục hồi, attacker ký được token giả mà **verifier lỗi/không rotate** chấp nhận | Forged token accepted |
| HC4 | Signer vá (RFC 6979) ⇒ 0 lặp `r`, recovery thất bại; **key rotation** làm token giả từ khoá cũ bị từ chối | Re-test |

## C.2 Tiêu chí chấp nhận
- Với cặp chữ ký hợp lệ: `d_recovered·G == Q` (so sánh với public key trong JWKS) ở **100%** trường hợp.
- Detector `repeated_r`: precision = recall = 1.0 trên corpus có ground truth.
- Signer vá: `repeated_r == 0` trên ≥ **10⁵** chữ ký; recovery thất bại 100%; KAT RFC 6979 pass.
- Sau rotation: token ký bằng khoá cũ bị verifier từ chối ở 100% (`kid` không còn trong JWKS / key bị revoke).

## C.3 Kiến trúc hệ thống (S1)
```
 ┌────────────┐ sign(claims) ┌──────────────┐  JWT (header.payload.sig)  ┌───────────────┐
 │ Issuer app │─────────────►│ Lab Signer   │───────────────────────────►│ Verifier (RS) │
 └────────────┘              │ (v_vuln /    │                            │ alg pinned,   │
                             │  v_patched)  │                            │ kid→JWKS      │
                             └──────┬───────┘                            └───────▲───────┘
                                    │ log chữ ký (r,s,H)                         │ JWKS (pubkey)
                                    ▼                                            │
                             ┌──────────────┐   recover d   ┌─────────────┐  forged JWT
                             │ Observer /   ├──────────────►│ Attacker    ├─────────────┘
                             │ corpus D3    │               │ harness     │
                             └──────────────┘               └─────────────┘
```
- **Signer:** ECDSA P-256 + SHA-256, định dạng JWS `R‖S` (64 byte). Tự cài đặt hàm ký **nhận `k` tường minh** (chỉ để lab) rồi bọc thành 2 phiên bản:
  - `v_vuln`: sinh `k` theo *failure mode* (C.4).
  - `v_patched`: `k` theo **RFC 6979** (hoặc thư viện chuẩn đã pin).
- **Verifier tham chiếu:** `cryptography` (độc lập với code ký) — nhằm đảm bảo chữ ký sinh ra hợp lệ.
- **Verifier thử nghiệm:** pin `alg=ES256`, kiểm `kid`, `iss/aud/exp`; JWKS nạp từ file để mô phỏng rotation.
- Ghi chú: P-256 ở đây **không bị phá** — lỗi là *implementation* (nonce), nên dùng curve chuẩn hợp lệ với khoá disposable.

## C.4 Failure modes (vulnerable signer)
| Mode | Cơ chế `k` | Lớp (`nonce_class`) | Mô phỏng |
|------|-----------|---------------------|-----------|
| F1 | `k` hằng số | `reuse_constant` | Mã ký "cứng" k |
| F2 | PRNG seed từ thời gian thô/boot counter, restart nhiều lần | `reuse_restart` | Seed ∈ tập nhỏ ⇒ va chạm giữa các lần restart |
| F3 | Với xác suất `ρ`, dùng lại `k` trước đó | `reuse_sparse` | Rò rỉ lẻ tẻ (race/cache) |
| F4 | `k` có entropy thấp (vd 32-bit) | `low_entropy` | (tuỳ chọn, L4 — liệt kê ứng viên) |
| G (control) | `k` từ CSPRNG | `random_ok` | Baseline an toàn |
| P (patched) | RFC 6979 | `deterministic` | Mitigation |

## C.5 Biến thí nghiệm
| Biến | Giá trị |
|------|---------|
| Số chữ ký quan sát `N` | 2, 10, 10², 10³, 10⁴, 10⁵ |
| `ρ` (F3) | 0, 10⁻⁴, 10⁻³, 10⁻², 10⁻¹, 1 |
| Kích thước tập seed (F2) | 2⁴, 2⁸, 2¹² |
| Số lần lặp thí nghiệm | 30 key lab độc lập / cấu hình (seed khác nhau) |
| Thông điệp | JWT claim ngẫu nhiên (`sub`, `jti`, `exp`) ⇒ `H_i` khác nhau |

## C.6 Luồng thực thi (pha)
```
 C0  Calibration   : kiểm signer = chữ ký hợp lệ (cryptography verify); KAT RFC 6979 cho v_patched
 C1  Key setup     : sinh khoá LAB-<seed>, đăng ký kid=v1 trong JWKS
 C2  Collection    : cho v_vuln ký N token; ghi (key_id, curve, msg_hash, r, s, nonce_class,
                     signer_version) vào D3 — *ground truth* `repeated_r` được gán riêng từ log nội bộ
 C3  Detection     : detector quét bảng băm theo r → liệt kê cặp (i,j) trùng r, H_i ≠ H_j
 C4  Recovery      : với mỗi cặp: tính k, d theo công thức; xác nhận d·G == Q
 C5  Impact        : tạo JWT {sub:"admin"} ký bằng d vừa khôi phục → gửi verifier (v1) ⇒ ghi accepted/rejected
 C6  Mitigation    : (a) thay signer = v_patched; (b) rotate khoá: kid=v2, gỡ v1 khỏi JWKS, revoke
 C7  Identical re-test: lặp C2–C5 y hệt (cùng seed/script) với signer vá + khoá mới; thử lại token giả từ d cũ
```

### Công thức & xử lý các ca biên
```
r1 = r2 = r;  s_i = k^{-1}(H_i + d·r) mod n
k = (H1 − H2)·(s1 − s2)^{-1} mod n
d = (s1·k − H1)·r^{-1} mod n
```
| Ca biên | Xử lý |
|---------|-------|
| `H1 == H2` (cùng thông điệp) | Chữ ký giống hệt ⇒ không phục hồi được; bỏ qua cặp |
| `s1 ≡ s2 (mod n)` | Không nghịch đảo được; bỏ qua |
| **Low-S / canonical hoá** (một chữ ký có thể bị đổi `s → n−s`) | Thử cả `±s_i` (tối đa 4 tổ hợp); chấp nhận tổ hợp cho `d·G == Q` |
| Cắt `H` theo độ dài `n` | Dùng cùng quy ước truncate với signer (SHA-256 vs 256-bit `n` ⇒ không cắt) |
| Hai khoá khác nhau trùng `r` | Không dùng cặp khác khoá; gắn nhãn khác `key_id` |
| Nhiều cặp trùng | Phục hồi mỗi cặp; nhất quán `d` ⇒ tăng độ tin cậy |

## C.7 Dữ liệu thu (Corpus D3 — schema)
```
key_id, curve, msg_hash, r, s, nonce_class, repeated_r(bool), leaked_bits_class(NA),
signer_version, run_id, seed, sig_index, jti, timestamp
```
**Bảng kết quả (`results/trackC/*.csv`):**
```
run_id, mode, N, rho, seed_space, sigs_to_first_repeat, pairs_found, detect_time_ms,
recovery_time_ms, d_recovered_ok, forged_token_accepted, signer_version, verifier_version
```

## C.8 Metric & phân tích
| Metric | Ý nghĩa |
|--------|---------|
| `sigs_to_first_repeat` | Số chữ ký quan sát cho đến khi có `r` lặp đầu tiên (median/IQR; F3 kỳ vọng ≈ `1/ρ` theo hình học — đối chiếu) |
| `recovery_time_ms` | Thời gian từ lúc có cặp đến khi có `d` (kỳ vọng ≪ 1 s) |
| `detect_time_ms` vs `N` | Độ phức tạp detector `O(N)` |
| Tỷ lệ phục hồi theo `(mode, N, ρ)` | Heatmap |
| `forged_token_accepted` | Tác động hệ thống (trước/sau mitigation) |
| So sánh work: thay vì `~2^128` ops, **vài** phép toán mod `n` | Đồ thị minh hoạ "collapse" |

Hình: FC1 CDF `sigs_to_first_repeat` theo `ρ`; FC2 heatmap `P(recover)` theo `(N,ρ)`; FC3 bảng before/after (accepted/rejected).

## C.9 Mitigation & lập luận bảo mật
| Mitigation | Vì sao chặn được | Residual risk (ghi vào báo cáo) |
|-----------|-------------------|----------------------------------|
| RFC 6979 deterministic `k` | `k = f(d, H)` ⇒ cùng thông điệp ⇒ cùng chữ ký; thông điệp khác ⇒ `k` khác | Không bảo vệ khỏi side-channel/fault; FIPS 186-5 chấp thuận nhưng internals vẫn cần bảo vệ |
| Key rotation + revocation (`kid`) | Khoá đã lộ không còn được verifier tin | Token cũ còn `exp` hợp lệ nếu cache JWKS → đặt TTL JWKS ngắn |
| Verifier pin `alg`/`crv`/`kid` | Chống alg/key confusion khi thử forged | Không thay thế rotation |
| Detector `repeated_r` trong CI/monitor | Phát hiện sớm sự cố | Chỉ phát hiện reuse chính xác, không phát hiện bias (→ Track E) |

## C.10 Rủi ro & mở rộng
- **Rủi ro:** lẫn lộn đồng thời "chữ ký hợp lệ" và "nonce ngẫu nhiên" — luôn có bước C0 calibration.
- **Mở rộng (tuỳ chọn):** biến thể **blockchain regtest** (secp256k1) cho S3: chạy node regtest cục bộ, ví lab tái dùng `k`; tuân thủ low-S như ca biên trên; **cấm** dùng public chain.
- **Cao học:** thêm Track E (bias/HNP) dùng cùng khung `D3` với `leaked_bits_class`.

## C.11 Đầu ra Track C
`data/D3.csv`, mã signer `v_vuln`/`v_patched`, `detector.py`, `recover.py`, FC1–FC3, bảng before/after, bản ghi rotation.

---

# TRACK D — Invalid-Curve / Small-Subgroup (Toy ECDH API)

## D.1 Mục tiêu & giả thuyết

| ID | Giả thuyết | Kiểm chứng |
|----|-----------|------------|
| HD1 | Service **không validate** peer point ⇒ mỗi điểm bậc nhỏ `rᵢ` lộ `d mod rᵢ`; CRT ghép được `d` khi `∏ rᵢ ≥ n` | Khôi phục `d` trên toy |
| HD2 | Với `h > 1`, điểm bậc nhỏ **trên đúng curve** cũng lộ `d mod (ước của h)` nếu thiếu subgroup check | Fixture toy `h > 1` |
| HD3 | **On-curve check** chặn invalid-curve; **subgroup check** chặn small-subgroup khi `h > 1` | Ma trận validator × point_class |
| HD4 | Chỉ validation chưa đủ nếu phản hồi lỗi/thời gian tạo ra oracle khác; cần phản hồi đồng nhất | Phân biệt phản hồi trước/sau |

**Lưu ý phân biệt (guideline):** đây là lỗi *validation* trên curve chuẩn mạnh, **không** chứng tỏ curve yếu (khác Track B).

## D.2 Tiêu chí chấp nhận
- Fixture vulnerable: khôi phục đúng `d` (so với ground truth) ở ≥ 95% trial; ghi `queries` & `bits_leaked`.
- Fixture patched (on-curve + subgroup + phản hồi đồng nhất): `bits_leaked == 0`, `d` không khôi phục; validator trả đúng nhãn mong đợi trên **100%** D4.
- Corpus D4 có đủ 6 lớp điểm (D.4) và kết quả validator khớp bảng kỳ vọng.

## D.3 Mô hình & fixture

```
 ┌──────────┐  peer point P (x,y)   ┌────────────────────────────┐
 │ Attacker │──────────────────────►│ ECDH API (toy, Weierstrass)│
 │ (toy     │                       │  d_dh bí mật (LAB-)        │
 │ harness) │◄──────────────────────│  S = d·P  ;  resp = f(S)   │
 └──────────┘   oracle response     └────────────────────────────┘
                 (value oracle / accept-reject oracle)
```

**Cấu hình toy:**
- `curve_main`: prime-order toy từ Track A (`h = 1`, `n` 24–40 bit) cho invalid-curve.
- `curve_cof`: toy có `h > 1` (ví dụ `p=97, a=2, b=3`, `G` bậc 50, `h=2` từ `math_notes.md`) cho small-subgroup.
- **Hai loại oracle (quan trọng, ảnh hưởng số query):**

| Oracle | Phản hồi | Cách attacker suy residue | Số query |
|--------|----------|----------------------------|----------|
| **O1 — Value oracle** | Trả `H(x(S))` hoặc ciphertext xác định bởi `S` | So khớp **offline** với `H(x(j·Pᵢ))`, `j<rᵢ` | ≈ số điểm dùng (`~k`, mỗi `rᵢ` một query) |
| **O2 — Accept/reject (MAC) oracle** | Chỉ báo MAC đúng/sai | Thử từng giả thuyết `j` ⇒ mỗi giả thuyết là một query | ≈ `Σ rᵢ` (trung bình `Σ rᵢ/2`) |

- Nếu oracle chỉ dùng toạ độ `x(S)`, residue xác định **chỉ đến dấu** (`±d mod rᵢ`) ⇒ phải ghép tổ hợp dấu (≤ `2^k` ứng viên, lọc bằng `d·G == Q`) hoặc thêm điểm.

## D.4 Corpus D4 — lớp điểm kiểm thử
| `point_class` | Mô tả | `on_curve` | `subgroup_class` | Kỳ vọng validator vá |
|---------------|-------|-----------|------------------|----------------------|
| `valid` | Điểm ngẫu nhiên trong `⟨G⟩` | T | in_subgroup | **accept** |
| `infinity` | `O` | — | — | reject |
| `out_of_range` | `x` hoặc `y ≥ p` / không canonical | — | — | reject |
| `wrong_curve` | Điểm thuộc `E'(b')`, `b' ≠ b`, bậc nhỏ | **F** | — | reject (on-curve) |
| `small_subgroup` | Điểm **trên** `E` nhưng bậc là ước của `h` (chỉ `curve_cof`) | T | small_order | reject (subgroup/cofactor) |
| `on_curve_not_in_G` | Trên `E`, ngoài `⟨G⟩` (`h>1`) | T | outside | reject |
| (tuỳ chọn) `twist_point` | Điểm trên twist (x-only API) | — | — | reject / thiết kế twist-secure |
Schema: `curve_id, point_class, on_curve, subgroup_class, validator_result, protocol_result, point_order, expected, match`.

## D.5 Luồng thực thi (pha)
```
 D0  Fixture setup : sinh curve_main/curve_cof (D1); sinh d_dh = LAB-seed; xuất public key Q
 D1  Sinh D4       : tạo điểm cho từng lớp (point_class) với ground truth bậc & curve
 D2  Validator test: chạy validators (v0 none, v1 on-curve, v2 on-curve+subgroup) trên D4
                     → ma trận validator × point_class; so với bảng kỳ vọng
 D3  Vulnerable run: service_vuln (v0) + oracle O1 (rồi O2)
        for i in 1..k: chọn E'ᵢ (b'ᵢ) có ước nhỏ rᵢ (đôi một nguyên tố cùng nhau);
                       Pᵢ ← điểm bậc rᵢ;  gửi Pᵢ;  suy d mod rᵢ (hoặc ±)
        CRT ghép ⇒ d ;  kiểm tra d·G == Q
        ghi: queries, bits_leaked = Σ log₂ rᵢ, candidate_space = n / ∏ rᵢ
 D4  Mitigation    : bật v2 (on-curve + subgroup + cofactor clearing nếu h>1)
                     + phản hồi lỗi đồng nhất (cùng mã, cùng độ trễ) + giới hạn tần suất
 D5  Identical re-test : chạy lại D3 (cùng script, cùng seed) vs service_patched
                     → kỳ vọng queries bị reject ngay, bits_leaked = 0
```

### D.3 (chi tiết) Chọn `E'ᵢ` và điểm bậc nhỏ — mức thiết kế
- Duyệt `b'` ≠ `b` (cùng `p, a`), loại curve singular; đếm `#E'(b')` bằng PARI/Sage.
- Giữ `b'` mà `#E'` có ước nguyên tố nhỏ `r` (≤ 2¹⁰, chưa dùng); điểm bậc `r` = `(#E'/r)·R` với `R` ngẫu nhiên, `≠ O`.
- Dừng khi `∏ rᵢ ≥ n` (hoặc `≥ n/2` kết hợp tìm kiếm cuối).
- Code attacker **chỉ chấp nhận** curve toy (`assert n_bits <= 40`, `LAB-` key) — xem 1.5.

## D.6 Biến thí nghiệm
| Biến | Giá trị |
|------|---------|
| `n_bits` (curve_main) | 24, 32, 40 |
| Loại oracle | O1, O2 |
| Dạng phản hồi | dùng `y` đầy đủ vs chỉ `x` (kiểm tra tác động của ± ) |
| Validator | v0 (none), v1 (on-curve), v2 (on-curve + subgroup) |
| Biến thể `h` | `h=1` (invalid-curve), `h>1` (small-subgroup) |
| Số trial | 30/cấu hình (key + seed khác nhau) |

## D.7 Ma trận ablation (validator × tấn công)
| Validator \ Tấn công | wrong_curve (`h=1`) | small_subgroup (`h>1`) | valid point |
|----------------------|:--:|:--:|:--:|
| v0 none | **leak** | **leak** | OK |
| v1 on-curve | blocked | **leak** | OK |
| v2 on-curve + subgroup/cofactor | blocked | blocked | OK |
| v2 + phản hồi đồng nhất | blocked + không oracle | blocked + không oracle | OK |
(Mỗi ô được xác nhận bằng thực nghiệm; `leak` = `bits_leaked > 0`.)

## D.8 Dữ liệu & metric
**Kết quả (`results/trackD/*.csv`):**
```
run_id, curve_id, n_bits, oracle_type, resp_form, validator, h, trial, seed,
queries, residues_found, bits_leaked, candidate_space_bits_before,
candidate_space_bits_after, recovered, wall_time_ms, response_class_uniform
```
| Metric | Ý nghĩa |
|--------|---------|
| `queries` | Số lần gọi oracle (O1 ≈ `k`, O2 ≈ `Σ rᵢ/2`) |
| `bits_leaked` | `Σ log₂ rᵢ` |
| Candidate-space shrink | `log₂ n → log₂ n − bits_leaked` theo số query |
| `validator_result` đúng | % khớp bảng kỳ vọng D4 |
| `response_class_uniform` | Phản hồi valid/invalid không phân biệt (nội dung + độ trễ, kiểm định thống kê) |

Hình: FD1 candidate-space shrink vs `queries` (vuln vs patched); FD2 `queries` O1 vs O2 theo `n_bits`; FD3 ma trận ablation (heatmap); FD4 phân phối độ trễ valid vs invalid (patched).

## D.9 Mitigation & lập luận bảo mật
| Mitigation | Vì sao chặn được | Residual |
|-----------|-------------------|----------|
| Not-∞, range, **on-curve** | Loại điểm `E'` ngay ở TB2 | Không chặn small-subgroup khi `h>1` |
| **Subgroup check** `nP=O` hoặc **cofactor clearing** | Loại/triệt điểm bậc nhỏ | Chi phí 1 scalar mult; chọn theo scheme (theo SP 800-56A — cần đối chiếu bản gốc) |
| Phản hồi lỗi đồng nhất + rate limit | Không biến feedback thành oracle (cf. CVE-2019-9155) | Side-channel thời gian còn lại |
| Rotate `d_dh` khi nghi ngờ | Hạn chế lộ luỹ tiến | Cần quy trình vận hành |
| X25519 (nhánh nhẹ, tuỳ chọn) | Thiết kế twist-secure; kiểm **all-zero shared secret** theo RFC 7748, **không** máy móc áp luật Weierstrass | Kiểm bằng danh sách điểm bậc nhỏ đã biết |

## D.10 Rủi ro & ca biên
| Rủi ro | Xử lý |
|--------|-------|
| `E'` không có ước nhỏ phù hợp ở `p` nhỏ | Tăng khoảng `b'` duyệt; chấp nhận `rᵢ` lớn hơn hoặc dùng `p` lớn hơn |
| `rᵢ` trùng giữa các curve | Dùng lcm hoặc loại trùng để CRT hợp lệ |
| Dấu `±` làm nhân đôi ứng viên | Tổ hợp dấu + lọc bằng `Q` |
| Oracle nhiễu | Lặp query, đa số phiếu (ghi vào `queries`) |
| Nhầm lẫn với weak-curve | Ghi rõ: curve chuẩn không yếu; lỗi ở validator |

## D.11 Đầu ra Track D
`data/D4.csv`, `service_vuln`/`service_patched`, `validators.py`, `attacker_toy.py` (khoá cứng giới hạn toy), FD1–FD4, bảng ablation, log validation.

---

## E. Kế hoạch thực hiện & phụ thuộc

| Tuần | Việc | Đầu ra | Phụ thuộc |
|------|------|--------|-----------|
| 3 | Track A: sinh D1, pilot, chạy 3 thuật toán, phân tích slope | D1, D2, FA1–FA4 | — |
| 5 | Track C: C0–C2 (signer, JWT, corpus) | D3 (vuln) | `ecc.py` từ A |
| 6 | Track C: C3–C7 (detect, recover, impact, vá, rotate, re-test) | Bảng before/after | Tuần 5 |
| 7 | Track D: D0–D5 + ablation | D4, FD1–FD4 | `curves` từ A |
| 10–11 | Gộp metric, residual-risk, đưa vào báo cáo | `results/summary.md` | A, C, D |

## F. Checklist nghiệm thu (đối chiếu đề)
- [ ] A: brute force vs generic ECDLP phân biệt bằng slope thực nghiệm; curve chuẩn chỉ là negative control.
- [ ] C: có vulnerable baseline, evidence (repeated-r + recovery), mitigation (RFC 6979 + rotation), **identical re-test**.
- [ ] D: invalid-curve tách bạch với weak-curve; validation justify theo giao thức; đủ 6 lớp điểm D4; ablation validator.
- [ ] Mọi track: seed/commit/version ghi trong CSV; không có secret production; assumptions & residual risk nêu rõ.
- [ ] Cử nhân: ≥ 3 track gồm nonce reuse **hoặc** invalid-curve **và** một kịch bản hệ thống hiện hành (C đáp ứng bằng JWT lab).
- [ ] Cao học: mở rộng CI/phân phối/ablation; cân nhắc nối sang Track E/F.

## G. Câu hỏi mở `[TODO]`
1. Chốt `n_bits` trần sau pilot Track A (Python hay C?).
2. Track C dùng JWT thuần hay thêm regtest secp256k1?
3. Track D: O1, O2 hay cả hai? Có thêm nhánh X25519 không?
4. Công cụ đếm điểm: Sage hay PARI (`cypari2`)?