# Nonce Theory — Khôi phục khóa riêng `d` từ 2 chữ ký ECDSA trùng nonce `k`

> **Vai trò tài liệu:** phân tích lý thuyết làm nền cho `signatures/vulnerable_signer.py` (sinh dữ liệu) và
> `signatures/nonce_reuse_attacker.py` (cài thuật toán) — xem Mục 7 cho pseudocode triển khai trực tiếp.
> **Liên kết:** `docs/threat_model.md` (tầng sụp đổ L3), `signatures/base_signer.py` (hàm `sign_with_k`,
> `_mod_inv`), `data/schema_definition.json` (dataset D3 — trường `nonce_class`, `repeated_r`).

---

## 1. Vì sao đây là lỗi *implementation*, không phải lỗi ECDLP

Ký ECDSA không yêu cầu phải "giải" bài toán khó nào — độ an toàn của nó dựa
hoàn toàn vào một giả định phụ: **nonce `k` là bí mật, duy nhất cho mỗi lần
ký, và không đoán được.** Nếu giả định này bị vi phạm, khóa riêng `d` lộ ra
bằng **đại số sơ cấp** — vài phép nghịch đảo modulo, không đụng đến bài toán
ECDLP. Đây chính là tầng **L3** trong `docs/threat_model.md`: work factor sụp
đổ từ `O(√n) ≈ 2^128` (Track A) xuống **O(1)** (vài phép tính mod `n`).

Điều này tách bạch rõ với Track A/B: `n` ở đây có thể là order 256-bit của
P-256 — curve **không hề yếu** — nhưng nếu nonce bị tái sử dụng, độ lớn của
`n` không còn ý nghĩa bảo vệ gì cả.

---

## 2. Ký hiệu & thiết lập bài toán

Cho đường cong với bậc nhóm `n`, điểm sinh `G`, khóa riêng `d ∈ [1, n-1]`,
khóa công khai `Q = d·G`. Để ký thông điệp `m`:

```
e = H(m) truncate về n_bits       (FIPS 186-5 §6.4 — cắt hash về tối đa bit(n))
k ∈ [1, n-1]  ngẫu nhiên (lẽ ra phải duy nhất mỗi lần ký)
R = k·G  = (x_R, y_R)
r = x_R mod n            (nếu r = 0 → chọn lại k)
s = k⁻¹ (e + r·d) mod n  (nếu s = 0 → chọn lại k)
chữ ký = (r, s)
```

**Giả sử attacker quan sát được 2 chữ ký từ cùng một khóa `d`, ký bằng cùng
một `k`, trên 2 thông điệp khác nhau `m₁ ≠ m₂`:**

```
s₁ = k⁻¹ (e₁ + r·d) mod n      (1)
s₂ = k⁻¹ (e₂ + r·d) mod n      (2)
```

Lưu ý: `r` giống hệt nhau ở cả 2 chữ ký — vì `r = x(kG) mod n` chỉ phụ thuộc
vào `k` (và domain parameters), **không phụ thuộc thông điệp**. Đây là lý do
`repeated_r` (2 chữ ký cùng khóa có cùng `r`) là tín hiệu quan sát được trực
tiếp từ bên ngoài để phát hiện nonce reuse, mà không cần biết `k` trước — đúng
cơ chế của `signatures/repeated_r_detector.py` (việc của Tuần 6).

---

## 3. Suy ra công thức khôi phục

Lấy (1) trừ (2):

```
s₁ - s₂ = k⁻¹ (e₁ - e₂) mod n
```

Vì `k⁻¹` là hằng số chung, nhân cả hai vế với `k`:

```
k·(s₁ - s₂) ≡ (e₁ - e₂)   (mod n)
```

Nếu `(s₁ - s₂) mod n ≠ 0`, nó khả nghịch modulo `n` (vì `n` — ở các curve
chuẩn — là số nguyên tố, mọi phần tử khác 0 đều khả nghịch):

```
                e₁ - e₂
    k = ───────────────────── mod n                              (3)
              s₁ - s₂
```

Có `k`, thay lại vào (1) để suy `d` từ `s₁ = k⁻¹(e₁ + r·d) mod n`:

```
    k·s₁ ≡ e₁ + r·d        (mod n)
    d = (k·s₁ - e₁) · r⁻¹  mod n                                  (4)
```

(Có thể dùng `s₂, e₂` thay cho `s₁, e₁` trong (4) — cho cùng kết quả, dùng để
**tự kiểm chéo**.)

### Công thức cuối

```
         e₁ - e₂                                    k·s₁ - e₁
    k = ───────── mod n            ,            d = ─────────  mod n
         s₁ - s₂                                         r
```

### Vì sao đúng (sketch chứng minh)

Trừ trực tiếp hai phương trình tuyến tính (1)–(2) theo `d` và `1/k` triệt
tiêu được `d`, chỉ còn phương trình bậc nhất theo `k` → giải ra `k` duy nhất
(với điều kiện mẫu số khác 0). Thế `k` ngược lại một trong hai phương trình
gốc, vốn tuyến tính theo `d`, cho nghiệm `d` duy nhất. Toàn bộ suy luận chỉ
dùng các phép toán trường hữu hạn `F_n` (cộng, trừ, nhân, nghịch đảo) —
**không có bước nào cần giải ECDLP.**

**Độ phức tạp:** O(1) phép modular arithmetic (2 lần nghịch đảo modulo bằng
thuật toán Euclid mở rộng, mỗi lần O(log n)). So với Track A (`O(√n) ≈
2^128` phép toán nhóm cho P-256), đây là sự sụp đổ **theo cấp số nhân** của
work factor.

---

## 4. Ví dụ số thực tế (đã chạy và kiểm chứng bằng `signatures/base_signer.py`)

Dùng `BaseECDSASigner.sign_with_k()` trên curve P-256 thật, khóa `d` ngẫu
nhiên, cố tình tái sử dụng `k` cho 2 thông điệp khác nhau:

```
d_true = 47869413735693839105250453554563367401109074409504834574194875664342912040178
n      = 115792089210356248762697446949407573529996955224135760342422259061068512044369
k (tái dùng) = 75919041071202825383861814738900562764560114271395362342056696488400179330552

msg1 = b"transfer:amount=10:to=alice"
  e1 = 12745740057547545453686505136801662011990787690280459941912199718068843722046
  r  = 112806334657283254450574267127485043756957647123601708496340059433847579011350
  s1 = 75051357470768930574052585142463881063840684631429406290270860567229645146801

msg2 = b"transfer:amount=99999:to=mallory"
  e2 = 113980322460162140445674454101612097947369204666606347344595370062330876933125
  r  = 112806334657283254450574267127485043756957647123601708496340059433847579011350   <- GIỐNG sig1
  s2 = 105867224474856908227141364413623511570928778864298305594056175154773753197693
```

Áp dụng công thức (3)–(4):

```
k_recovered = (e1-e2) * inverse(s1-s2, n) mod n
            = 75919041071202825383861814738900562764560114271395362342056696488400179330552
            = k (TRÙNG KHỚP)

d_recovered = (k_recovered*s1 - e1) * inverse(r, n) mod n
            = 47869413735693839105250453554563367401109074409504834574194875664342912040178
            = d_true (TRÙNG KHỚP)
```

Toàn bộ quá trình tốn **2 phép nghịch đảo modulo** — không có vòng lặp tìm
kiếm nào. Script tái lập (sẽ đưa vào `signatures/test_nonce_attack.py` ở
Tuần 5–6):

```python
from signatures.base_signer import BaseECDSASigner, _mod_inv

def recover_d_from_two_sigs(curve, e1, r1, s1, e2, r2, s2):
    n = curve.n
    assert r1 % n == r2 % n, "2 chữ ký không cùng r -> không chắc cùng k"
    denom = (s1 - s2) % n
    if denom == 0:
        raise ValueError("s1 == s2 (mod n): có thể e1==e2 (cùng thông điệp) "
                          "hoặc trùng ngẫu nhiên hiếm gặp -> không giải được từ cặp này")
    k = ((e1 - e2) * _mod_inv(denom, n)) % n
    d = ((k * s1 - e1) * _mod_inv(r1, n)) % n
    return k, d
```

---

## 5. Các ca biên — PHẢI xử lý trong `nonce_reuse_attacker.py`

Đây là phần dễ bị bỏ sót nhất khi cài đặt; mỗi ca biên dưới đây đã được chạy
thử nghiệm thực tế để xác nhận hành vi.

### 5.1 `e₁ = e₂` (ký đúng 1 thông điệp 2 lần) → không giải được

Nếu `m₁ = m₂` thì `e₁ = e₂`, kéo theo `s₁ = s₂` (vì (1) và (2) trở thành
cùng một phương trình) → `s₁ - s₂ ≡ 0 (mod n)` → **không nghịch đảo được**.

Đã kiểm chứng: ký cùng `msg1` hai lần với cùng `k` cho `r₁=r₂` và `s₁=s₂`
tuyệt đối, `(s₁-s₂) mod n = 0`.

> **Hệ quả thiết kế:** `nonce_reuse_attacker.py` cần kiểm tra `e₁ ≠ e₂` (hoặc
> tương đương `s₁ ≢ s₂ mod n`) trước khi chia; nếu phát hiện trùng, loại cặp
> đó và tìm cặp khác trong cùng nhóm `repeated_r` (xem Mục 6).

### 5.2 Mơ hồ dấu do canonical hoá chữ ký ("low-S")

ECDSA có tính malleable: với mọi chữ ký hợp lệ `(r, s)`, cặp `(r, n-s)` **cũng
hợp lệ** cho cùng thông điệp/khóa (ứng với việc dùng `-k` thay vì `k`). Nhiều
thư viện/chuẩn (vd Bitcoin's BIP 62, một số JWS implementation) **chuẩn hoá**
về "low-S" (`s ≤ n/2`) trước khi lưu/phát hành. Nếu dữ liệu attacker thu thập
đã bị chuẩn hoá, `s` quan sát được có thể **khác** với `s` gốc tại thời điểm
ký (bị "lật dấu" thành `n-s`), khiến công thức (3)–(4) cho **sai `d`** nếu áp
dụng trực tiếp.

Đã kiểm chứng bằng mô phỏng: sau khi lật `s₂ → n-s₂`, áp công thức trực tiếp
cho `d_recovered ≠ d_true`. Thử đủ 4 tổ hợp dấu `{s₁, n-s₁} × {s₂, n-s₂}` thì
tìm đúng tổ hợp cho `d` khớp khóa công khai.

> **Hệ quả thiết kế:** thuật toán khôi phục phải thử tối đa 4 tổ hợp
> `(±s₁, ±s₂)` (ký hiệu `±s := {s, n-s}`), và **chốt nghiệm bằng cách kiểm
> tra độc lập** `d·G == Q` (public key đã biết) — không chỉ tin vào kết quả
> phép chia đầu tiên. Đây cũng là lý do `signatures/base_signer.py.verify()`
> nên được gọi lại sau khi phục hồi `d`, như một "oracle xác nhận" cuối cùng.

### 5.3 Trùng `r` ngẫu nhiên nhưng **khác** `k` (hiếm, chỉ đáng lo ở curve nhỏ)

Về lý thuyết, `r₁ = r₂` không *buộc* phải do `k₁ = k₂` — có thể 2 giá trị
`k` khác nhau tình cờ cho cùng `x(kG) mod n` (một dạng va chạm). Xác suất
việc này xảy ra ngẫu nhiên là khoảng `1/n` theo mỗi cặp so sánh — với P-256
(`n ≈ 2^256`) đây là **không đáng kể trong thực tế** (an toàn để coi
`repeated_r ⇒ repeated_k`). Với toy curve `n` nhỏ (Track A, không dùng cho
Track C) xác suất này không còn nhỏ — một lý do nữa Track C **chỉ** chạy trên
P-256 thật (`system-demos/jwt-es256`), không chạy trên toy curve.

> **Hệ quả thiết kế:** khi `nonce_reuse_attacker.py` phục hồi được `d`, LUÔN
> xác nhận bằng `d·G == Q`. Nếu một nhóm `repeated_r` trong D3 vô tình gộp
> chữ ký từ **2 `key_id` khác nhau** (lỗi sinh corpus), phép thử sẽ tự nhiên
> cho `d` không khớp `Q` của bất kỳ khóa nào — là tín hiệu để
> `signatures/test_nonce_attack.py` bắt lỗi dữ liệu thay vì báo nhầm thành
> công.

### 5.4 Chỉ có 1 chữ ký quan sát được với 1 giá trị `r`

Công thức cần **ít nhất 2** chữ ký cùng `r` (từ cùng khóa). Một chữ ký đơn lẻ
không rò rỉ gì cả — đây là lý do metric `sigs_to_first_repeat`
(`docs/experimental_design.md` C.8) là đại lượng trung tâm để đo "cần quan
sát bao nhiêu chữ ký thì xảy ra vụ reuse đầu tiên".

---

## 6. Tổng quát hoá: `m ≥ 2` chữ ký cùng chia sẻ `k`

Nếu một khóa `k` bị tái sử dụng cho `m > 2` thông điệp (ví dụ failure mode
`reuse_constant` trong `nonce_class` — *mọi* chữ ký của khóa đó dùng cùng
`k`), ta có `m` phương trình tuyến tính cùng dạng (1). Khi đó:

- **Không cần giải đồng thời cả hệ** — chỉ cần đúng **1 cặp** `(i, j)` với
  `eᵢ ≠ eⱼ` áp công thức (3)–(4) là đủ để lộ toàn bộ `d`.
- **Dùng dư để tăng độ tin cậy:** tính `d` từ mọi cặp `(i,j)` có `r` trùng
  nhau; nếu tất cả cho cùng 1 giá trị `d` (và `d·G == Q`), đó là bằng chứng
  chắc chắn. Nếu các cặp cho `d` khác nhau, đó là dấu hiệu: (a) nhầm nhóm
  `repeated_r` giữa 2 khóa (ca biên 5.3), hoặc (b) lỗi canonical hoá (ca biên
  5.2) chưa xử lý hết tổ hợp dấu.
- **Không cải thiện gì thêm về mặt lý thuyết** — ngay cả `m = 2` đã đủ phá
  hoàn toàn khóa; `m` lớn hơn chỉ tăng **số cặp khả dụng** (và do đó giảm số
  chữ ký attacker cần chờ quan sát), không làm bài toán "dễ hơn" về bản chất
  toán học.

### Liên hệ với 3 cơ chế lỗi (`nonce_class`) trong `data/schema_definition.json`

| `nonce_class` | Cơ chế | Hệ quả lên việc chọn cặp để phục hồi |
|---|---|---|
| `reuse_constant` | `k` hằng số cho **mọi** chữ ký của khóa | Bất kỳ 2 chữ ký nào (khác thông điệp) của khóa đó đều dùng được — cặp đầu tiên tìm thấy là đủ. |
| `reuse_restart` | `k` phụ thuộc seed hẹp, lặp lại sau mỗi lần restart | Chỉ các chữ ký **cùng seed** (thường là cùng "đợt chạy") mới trùng `r`; cần nhóm theo `run_id`/epoch trước khi tìm cặp. |
| `reuse_sparse` | Với xác suất `ρ`, `k` bị chọn lại ngẫu nhiên trong tập đã dùng | Trùng `r` xuất hiện thưa thớt, ngẫu nhiên trong toàn bộ stream; cần quét toàn bộ lịch sử chữ ký, không gộp theo đợt. |

Cả 3 trường hợp đều dùng **chung một công thức khôi phục** (Mục 3) — khác
nhau chỉ ở **cách tìm ra cặp `(i,j)` có `r` trùng** (đó là việc của
`repeated_r_detector.py`, Tuần 6), không phải ở thuật toán khôi phục `d`.

---

## 7. Pseudocode triển khai (cho `signatures/nonce_reuse_attacker.py`)

```
HÀM recover_private_key(curve, signatures_cung_r: List[Signature]) -> Optional[int]:
    # signatures_cung_r: >=2 chữ ký đã được repeated_r_detector xác nhận cùng r,
    # LƯU Ý: có thể đến từ nhiều key_id nếu detector lỗi -> phải tự kiểm ở bước cuối.
    n = curve.n
    r = signatures_cung_r[0].r
    ỨNG_VIÊN_D = {}  # d -> số phiếu (để lấy đa số nếu có >2 chữ ký)

    CHO MỖI cặp (sig_i, sig_j) trong tổ_hợp_2(signatures_cung_r):
        e_i, _ = hash_message(curve, sig_i.msg)
        e_j, _ = hash_message(curve, sig_j.msg)
        s_i_raw, s_j_raw = int(sig_i.s), int(sig_j.s)

        CHO MỖI (s_i, s_j) TRONG {s_i_raw, n - s_i_raw} × {s_j_raw, n - s_j_raw}:  # ca biên 5.2
            denom = (s_i - s_j) mod n
            NẾU denom == 0: TIẾP TỤC                                            # ca biên 5.1
            k = ((e_i - e_j) * nghịch_đảo(denom, n)) mod n
            d_ung_vien = ((k * s_i - e_i) * nghịch_đảo(r, n)) mod n

            NẾU d_ung_vien * G == Q_cong_khai:                                   # xác nhận bắt buộc
                ỨNG_VIÊN_D[d_ung_vien] += 1

    NẾU ỨNG_VIÊN_D rỗng:
        TRẢ VỀ None   # không phục hồi được từ nhóm này (toàn bộ cặp đều là ca biên 5.1)

    TRẢ VỀ d có số phiếu cao nhất trong ỨNG_VIÊN_D   # ca biên 5.3: nếu có >1 giá trị
                                                       # khác nhau đều pass xác nhận, đó là
                                                       # dấu hiệu bất thường cần log cảnh báo
```

Điểm mấu chốt khi hiện thực hoá:
1. **Luôn xác nhận bằng `d·G == Q`** trước khi chấp nhận kết quả (không chỉ tin phép chia).
2. **Thử cả 4 tổ hợp dấu** `(±s_i, ±s_j)` để không bỏ sót trường hợp dữ liệu đã bị chuẩn hoá low-S.
3. **Bỏ qua, không crash**, khi gặp `denom == 0` — chuyển sang cặp kế tiếp.
4. Khi có `m > 2` chữ ký cùng `r`, dùng **đa số phiếu** trên mọi cặp hợp lệ làm tín hiệu chất lượng dữ liệu, không chỉ lấy kết quả của cặp đầu tiên.

---

## 8. Tiền đề đầu vào: từ đâu có "2 chữ ký cùng `r`"?

Công thức ở Mục 3 **giả định đã có sẵn** một cặp chữ ký cùng `r`. Việc tìm ra
cặp đó trong một luồng chữ ký là việc của `signatures/repeated_r_detector.py`
(Tuần 6) — về bản chất chỉ là tra bảng băm `r → [chữ ký]`, độ phức tạp
`O(N)` với `N` chữ ký quan sát được, đúng như `docs/experimental_design.md`
mô tả. Tài liệu này chỉ tập trung vào bước **sau khi đã có cặp** — "cặp cùng
`r` đó cho ta gì".

---

## 9. Ghi nhận thực tế (bối cảnh, không phải trích dẫn kỹ thuật)

Lớp tấn công này không phải lý thuyết suông — 2 sự cố được ghi nhận rộng rãi
trong cộng đồng bảo mật minh hoạ đúng cơ chế ở Mục 3:

- **Sony PlayStation 3 (2010):** nhóm fail0verflow/geohot công bố đã khôi
  phục khóa ký ECDSA gốc của Sony vì firmware dùng **một giá trị `k` cố định**
  cho mọi chữ ký (ứng với `nonce_class = reuse_constant` trong phân loại của
  nhóm) — chỉ cần 2 chữ ký bất kỳ là đủ.
- **Lỗ hổng `SecureRandom` trên Android (2013):** một số phiên bản Android có
  bộ sinh số ngẫu nhiên bị lỗi, khiến nhiều ví Bitcoin ký giao dịch với `k`
  bị lặp lại (gần với `nonce_class = reuse_sparse`/`low_entropy` tuỳ nguyên
  nhân cụ thể), dẫn đến mất tiền do khóa riêng của ví bị suy ra công khai.

Hai sự cố trên dùng đúng công thức ở Mục 3 — khác nhau chỉ ở *cơ chế gây ra*
việc tái sử dụng `k` (lỗi thiết kế tường minh vs lỗi entropy), đúng với cách
Track C phân biệt `reuse_constant` / `reuse_restart` / `reuse_sparse` /
`low_entropy` như 4 **nguyên nhân** dẫn tới cùng 1 **hệ quả toán học**.

*(Đây là bối cảnh lịch sử được biết đến rộng rãi, không phải trích dẫn số
liệu kỹ thuật cụ thể cần kiểm chứng lại — nếu đưa vào báo cáo chính thức,
nhóm nên dẫn thêm nguồn thứ cấp uy tín khi cần.)*

---

## 10. Vì sao RFC 6979 (bản vá, Tuần 6) chặn được lớp tấn công này

`k` bị tái sử dụng vì nó được sinh **độc lập với nội dung ký** (CSPRNG lỗi,
hằng số, hay seed hẹp). RFC 6979 định nghĩa `k = f(d, H(m))` — **hàm tất
định** của khóa riêng và thông điệp (qua HMAC-DRBG). Hệ quả trực tiếp:

```
m₁ ≠ m₂  ⇒  H(m₁) ≠ H(m₂)  ⇒  k₁ = f(d, H(m₁)) ≠ k₂ = f(d, H(m₂))   (hầu như chắc chắn)
m₁ = m₂  ⇒  k₁ = k₂           (nhưng khi đó r₁=r₂, s₁=s₂ — chữ ký giống hệt,
                                 không rò rỉ gì thêm — đúng ca biên 5.1)
```

Nói cách khác, RFC 6979 không "ngẫu nhiên hoá tốt hơn" — nó **loại bỏ hoàn
toàn khả năng 2 thông điệp khác nhau vô tình dùng chung `k`**, bằng cách gắn
chặt `k` vào chính thông điệp. Đây là nội dung sẽ triển khai ở
`signatures/rfc6979_signer.py` và kiểm chứng lại bằng chính công thức ở Mục 3
(kỳ vọng: không tìm được cặp `r` trùng nào trên ≥ 10⁵ chữ ký — tiêu chí chấp
nhận đã đặt ở `docs/project_plan.md` §5).

---

## 11. Tổng kết cho các task tiếp theo

| File sẽ cài đặt | Dùng gì từ tài liệu này |
|---|---|
| `signatures/vulnerable_signer.py` | Biết chính xác cơ chế cần mô phỏng cho từng `nonce_class` (Mục 6) |
| `signatures/repeated_r_detector.py` | Biết `repeated_r` tương đương `k` trùng với xác suất áp đảo (Mục 5.3) |
| `signatures/nonce_reuse_attacker.py` | Pseudocode đầy đủ kèm 4 ca biên bắt buộc xử lý (Mục 5, Mục 7) |
| `signatures/test_nonce_attack.py` | Bộ ca biên để viết test: `e1=e2`, low-S flip, nhóm `r` lẫn khóa, `m>2` chữ ký | 
| `signatures/rfc6979_signer.py` | Lý do toán học vì sao bản vá này triệt tiêu tận gốc lớp lỗi (Mục 10) |

## Tham khảo
- [1] FIPS 186-5 — Digital Signature Standard, §6.4 (cắt hash về bit(n)).
- [2] RFC 6979 — Deterministic DSA/ECDSA, §3.2.
- [3] `curves/math_notes.md` §5 — ECDLP & work factor (đối chiếu O(1) vs O(√n)).
- [4] `docs/threat_model.md` — tầng sụp đổ L3 (nonce reuse).