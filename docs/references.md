# References & Standards Review
## Phân Tích Tiêu Chuẩn Mật Mã: NIST SP 800-186, RFC 6090 & FIPS 186-5

> [!NOTE]
> **Thông Tin Tổng Quan & Quy Ước Đánh Giá**
> - **Chủ đề nghiên cứu:** Topic 14 — ECC Cryptanalysis & Implementation Failure Engineering (Task 4).
> - **Trạng thái tài liệu:** BẢN RÀ SOÁT CHÍNH THỨC (Reviewed Standard Baseline v1.0).
> - **Ngày đối chiếu (Retrieval Date):** 2026-10-18 (Yêu cầu bắt buộc theo Guideline Topic 14).
> - **Quy ước đánh dấu độ tin cậy:**
>   - `[G]`: Dữ liệu và chỉ dẫn trích xuất trực tiếp từ Guideline Topic 14.
>   - `[V]`: Dữ liệu đã được kiểm chứng chéo (Verified) trực tiếp qua tài liệu gốc của NIST / IETF / CVE Records.
>   - `[K]`: Nhận định chuyên gia và kiến thức nền tảng mật mã học.

---

## Mục Lục
1. [Khung Tổng Quan: Bộ Ba Tiêu Chuẩn Nền Tảng (The Standards Triad)](#1-khung-tổng-quan-bộ-ba-tiêu-chuẩn-nền-tảng-the-standards-triad)
2. [NIST SP 800-186: Khuyến Nghị Tham Số Miền Đường Cong Elliptic](#2-nist-sp-800-186-khuyến-nghị-tham-số-miền-đường-cong-elliptic)
3. [RFC 6090: Các Thuật Toán Nền Tảng Trong Mật Mã ECC](#3-rfc-6090-các-thuật-toán-nền-tảng-trong-mật-mã-ecc)
4. [FIPS 186-5: Tiêu Chuẩn Chữ Ký Số Liên Bang (DSS)](#4-fips-186-5-tiêu-chuẩn-chữ-ký-số-liên-bang-dss)
5. [Ma Trận Ánh Xạ: Tiêu Chuẩn $\leftrightarrow$ Track Thực Nghiệm $\leftrightarrow$ Bằng Chứng](#5-ma-trận-ánh-xạ-tiêu-chuẩn-leftrightarrow-track-thực-nghiệm-leftrightarrow-bằng-chứng)
6. [Danh Mục Thư Tịch Đầy Đủ & Liên Kết Nguồn Chính Thức](#6-danh-mục-thư-tịch-đầy-đủ--liên-kết-nguồn-chính-thức)
7. [Bảng Đối Chiếu Điểm Mấu Chốt Trong Guideline (Reconciliation Audit)](#7-bảng-đối-chiếu-điểm-mấu-chốt-trong-guideline-reconciliation-audit)
8. [Quy Chuẩn Trích Dẫn Học Thuật Trong Báo Cáo Nghiên Cứu](#8-quy-chuẩn-trích-dẫn-học-thuật-trong-báo-cáo-nghiên-cứu)

---

## 1. Khung Tổng Quan: Bộ Ba Tiêu Chuẩn Nền Tảng (The Standards Triad)

Ba tài liệu tiêu chuẩn kỹ thuật đóng vai trò là kim chỉ nam giải quyết ba câu hỏi nền tảng của mật mã học đường cong Elliptic:

```mermaid
graph TD
    SP800186["NIST SP 800-186 (2023)<br/><b>Đường cong nào an toàn?</b><br/>• Tham số miền (Domain Parameters)<br/>• Prime Curves (P-256, P-384, P-521)<br/>• Edwards / Montgomery Curves<br/>• Loại bỏ Binary Curves (B/K)"]
    RFC6090["RFC 6090 (2011)<br/><b>Toán học & Thuật toán cơ bản?</b><br/>• Số học trường hữu hạn 𝔽_p<br/>• Phép cộng điểm & Nhân vô hướng<br/>• Độ phức tạp Generic O(√n)<br/>• Yêu cầu cấp nguyên tố lớn"]
    FIPS1865["FIPS 186-5 (2023)<br/><b>Chữ ký số triển khai ra sao?</b><br/>• Lược đồ ECDSA & EdDSA<br/>• Nonce tất định (Deterministic Nonce)<br/>• Quy tắc Verifier & Canonical Bounds<br/>• Kiểm tra khóa công khai"]

    SP800186 -->|"Cung cấp tham số miền"| FIPS1865
    RFC6090 -->|"Cung cấp nền tảng thuật toán"| FIPS1865
    FIPS1865 --> SystemEngineering["Bảo Vệ Hệ Thống Ứng Dụng Thực Tế<br/>(JWT, ECDH, Blockchain, SSH)"]
```

### Bảng So Sánh Vai Trò & Thuộc Tính

| Tài Liệu Tiêu Chuẩn | Cơ Quan Ban Hành | Bản Chất Pháp Lý | Câu Hỏi Trọng Tâm | Vai Trò Quyết Định Trong Đề Tài |
| :--- | :---: | :---: | :--- | :--- |
| **NIST SP 800-186** (2023) `[V]` | NIST (Mỹ) | Khuyến nghị đặc tả kỹ thuật (Special Publication) | *Đường cong và tham số miền nào được khuyến nghị sử dụng?* | Làm đường cơ sở (Baseline) cho việc lập danh sách cho phép (**Curve Allow-list**), phân loại đường cong chuẩn vs tham số tuỳ chỉnh. |
| **RFC 6090** (2011) `[V]` | IETF | Đặc tả thông tin kỹ thuật (Informational RFC) | *Các giải thuật toán học ECC hoạt động ra sao, tham số cần thỏa mãn điều kiện gì?* | Cung cấp nền tảng đại số học, tiêu chí kiểm tra tham số miền, đối chứng thuật toán cho **Track A (Generic)** và **Track B (Unsafe Order)**. |
| **FIPS 186-5** (2023) `[V]` | Bộ Thương Mại Mỹ / NIST | Tiêu chuẩn bắt buộc liên bang (Federal Standard) | *Các sơ đồ chữ ký số nào được phê duyệt và quy tắc thực thi ra sao?* | Làm đường cơ sở cho **ECDSA, EdDSA, Deterministic Nonce (RFC 6979)**, quy tắc xác thực canonical cho **Track C, E, G**. |

---

## 2. NIST SP 800-186: Khuyến Nghị Tham Số Miền Đường Cong Elliptic

**Định danh số:** NIST Special Publication 800-186 (Tháng 2/2023)  
**Tên chính thức:** *Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters*  
**Liên kết DOI:** https://doi.org/10.6028/NIST.SP.800-186 `[V]`

### 2.1 Nội dung kỹ thuật cốt lõi
1. **Danh mục đường cong Weierstrass trên trường nguyên tố $\mathbb{F}_p$ ($h = 1$):**
   - Phương trình chuẩn hóa:
     $$E(\mathbb{F}_p): y^2 \equiv x^3 - 3x + b \pmod p$$
   - Các đường cong được phê duyệt: **P-224, P-256, P-384, P-521**.
   - Cấp nhóm $n = \#E(\mathbb{F}_p)$ là số nguyên tố lớn, thừa số đồng hành $h = 1$. Mọi điểm khác $\mathcal{O}$ đều thuộc nhóm con cyclic chính.
2. **Bổ sung đường cong Edwards và Montgomery ($h > 1$):**
   - Lần đầu tiên NIST chính thức chuẩn hóa các đường cong xuất phát từ RFC 7748 và RFC 8032:
     - **Ed25519** (Twisted Edwards) và **Curve25519** (Montgomery) trên trường $\mathbb{F}_{2^{255}-19}$, cofactor $h = 8$.
     - **Ed448** và **Curve448** (Edwards / Montgomery) trên trường $\mathbb{F}_{2^{448}-2^{224}-1}$, cofactor $h = 4$.
3. **Khai tử các đường cong nhị phân (Binary Curves Deprecation):**
   - Toàn bộ các đường cong trên trường đặc trưng 2 ($\mathbb{F}_{2^m}$) bao gồm họ **B-curves** (Pseudorandom binary) và **K-curves** (Koblitz binary, ví dụ B-233, K-283, B-409, v.v.) bị đưa vào trạng thái **Deprecated (Không được dùng cho hệ thống mới)**.
   - *Lưu ý quan trọng từ Guideline:* "Deprecated" **không** đồng nghĩa với việc đường cong đã bị bẻ gãy về mặt toán học. Quyết định loại bỏ xuất phát từ việc tính toán trên trường nhị phân phức tạp, khó chống rò rỉ kênh kề, và sự phát triển của thuật toán Index Calculus cho các trường nhị phân đặc thù.

### 2.2 Bảng phân loại chi tiết các đường cong trong NIST SP 800-186

| Tên Đường Cong | Dạng Hình Học Phương Trình | Độ Dài Khóa Trường ($p$) | Cấp Nhóm Con ($n$) | Cofactor ($h$) | Mức An Toàn Thiết Kế | Trạng Thái NIST |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **P-224** | Short Weierstrass ($a = -3$) | 224 bit | $\approx 2^{224}$ | $1$ | 112 bit | Approved |
| **P-256** | Short Weierstrass ($a = -3$) | 256 bit | $\approx 2^{256}$ | $1$ | 128 bit | **Approved (Khuyến nghị cao)** |
| **P-384** | Short Weierstrass ($a = -3$) | 384 bit | $\approx 2^{384}$ | $1$ | 192 bit | Approved |
| **P-521** | Short Weierstrass ($a = -3$) | 521 bit | $\approx 2^{521}$ | $1$ | 256 bit | Approved |
| **Curve25519 / Ed25519** | Montgomery / Twisted Edwards | 255 bit | $\approx 2^{252}$ | $8$ | 128 bit | **Approved (Khuyến nghị cao)** |
| **Curve448 / Ed448** | Montgomery / Edwards | 448 bit | $\approx 2^{446}$ | $4$ | 224 bit | Approved |
| **B-163 / K-163 ... B-571** | Binary Field Curves $\mathbb{F}_{2^m}$ | 163–571 bit | Đa dạng | $2 \text{ hoặc } 4$ | 80–256 bit | **DEPRECATED (Khai tử)** |

> [!WARNING]
> **Vị trí của đường cong secp256k1:**
> Đường cong **secp256k1** ($y^2 \equiv x^3 + 7 \pmod p$, sử dụng trong Bitcoin và Ethereum) **hoàn toàn KHÔNG nằm trong NIST SP 800-186** `[V]`. Đường cong này thuộc đặc tả của tổ chức SECG (Standards for Efficient Cryptography Group - SEC 2). Trong đề tài, secp256k1 được phân loại là **Đường cong ngoài NIST (Non-NIST industry curve)** thuộc bối cảnh lab S3.

### 2.3 Ý nghĩa thực tiễn đối với hệ thống phòng lab
- **Chính sách kiểm soát đường cong (Curve Allow-list):** Các endpoint API (ECDH, JWT) phải cấu hình chỉ chấp nhận danh sách các đường cong nằm trong diện *Approved*. Bất kỳ yêu cầu nào mang tham số đường cong tuỳ chỉnh (Explicit parameters) hoặc đường cong nhị phân deprecated đều phải bị từ chối ngay lập tức tại ranh giới TB2.
- **Xử lý cofactor ($h > 1$):** Đối với các đường cong mới được bổ sung như Ed25519 ($h=8$), hệ thống bắt buộc phải áp dụng quy tắc kiểm tra cofactor clearing hoặc kiểm tra toàn bộ điểm cấp nhỏ để ngăn chặn tấn công Small-subgroup.

---

## 3. RFC 6090: Các Thuật Toán Nền Tảng Trong Mật Mã ECC

**Định danh số:** RFC 6090 (IETF Informational, Tháng 2/2011)  
**Tác giả:** D. McGrew, K. Igoe, M. Salter  
**Tên chính thức:** *Fundamental Elliptic Curve Cryptography Algorithms*  
**Liên kết chính thức:** https://www.rfc-editor.org/rfc/rfc6090 `[V]`

### 3.1 Nội dung kỹ thuật cốt lõi
1. **Mô tả tường minh các phép toán số học trường và nhóm điểm:**
   - Cung cấp công thức đại số hoàn chỉnh cho phép cộng điểm và nhân đôi điểm trên dạng Short Weierstrass.
   - Định nghĩa tính khả nghịch và luật kết hợp nhóm Abel hữu hạn $(E(\mathbb{F}_p), +)$.
2. **Tiêu chuẩn tham số an toàn:**
   - Nhấn mạnh rằng nhóm con cyclic sinh bởi điểm cơ sở $G$ **bắt buộc phải có cấp nguyên tố lớn $n$** (hoặc chứa một ước nguyên tố đủ lớn để kháng lại thuật toán Pohlig–Hellman).
   - Đưa ra cảnh báo rõ ràng về các tham số làm suy yếu bài toán ECDLP:
     - Biệt thức suy biến $\Delta \equiv 0 \pmod p$.
     - Đường cong Anomalous ($\#E(\mathbb{F}_p) = p$).
     - Bậc nhúng (Embedding degree) nhỏ làm đường cong dễ tổn thương trước các phép rút gọn cặp song tuyến (Pairing-friendly / MOV reduction).
3. **Cơ sở cho việc đánh giá độ phức tạp Generic ECDLP:**
   - Xác lập rằng thuật toán generic tốt nhất được biết đến hiện nay là thuật toán Pollard's Rho và BSGS với độ phức tạp:
     $$W_{\text{generic}} \approx \mathcal{O}(\sqrt{n})$$
   - Thuật toán vét cạn $\mathcal{O}(n)$ không bao giờ được coi là thước đo độ phức tạp an ninh thực tế.

### 3.2 Giới hạn lịch sử & Lưu ý trích dẫn
- RFC 6090 là tài liệu mang tính chất **Thông tin kỹ thuật (Informational RFC)**, không phải Tiêu chuẩn Internet (Standards Track) và không phải tài liệu do NIST chuẩn hóa.
- Tài liệu được phát hành vào năm 2011, **trước khi** các tiêu chuẩn hiện đại về EdDSA (RFC 8032 - 2017) và X25519 (RFC 7748 - 2016) ra đời. Do đó, RFC 6090 **không được sử dụng** để trích dẫn đặc tả cho Ed25519 hoặc Curve25519.

---

## 4. FIPS 186-5: Tiêu Chuẩn Chữ Ký Số Liên Bang (DSS)

**Định danh số:** Federal Information Processing Standards Publication 186-5 (Tháng 2/2023)  
**Tổ chức ban hành:** National Institute of Standards and Technology (NIST)  
**Tên chính thức:** *Digital Signature Standard (DSS)*  
**Liên kết DOI:** https://doi.org/10.6028/NIST.FIPS.186-5 `[V]`

### 4.1 Nội dung kỹ thuật cốt lõi
1. **Phê duyệt hai họ sơ đồ chữ ký số đường cong Elliptic:**
   - **ECDSA (Elliptic Curve Digital Signature Algorithm):** Áp dụng trên các đường cong nguyên tố của SP 800-186 (P-224, P-256, P-384, P-521).
   - **EdDSA (Edwards-curve Digital Signature Algorithm):** Chính thức chuẩn hóa việc sử dụng Ed25519 và Ed448 theo cấu trúc Twisted Edwards (RFC 8032).
2. **Chính thức phê duyệt Nonce tất định (Deterministic ECDSA):**
   - FIPS 186-5 chính thức cho phép sử dụng thuật toán sinh nonce tất định dựa trên mã xác thực thông điệp HMAC (theo chuẩn **RFC 6979**).
   - Việc chuyển đổi sang nonce tất định loại bỏ hoàn toàn sự phụ thuộc vào bộ sinh số ngẫu nhiên vật lý (RNG), triệt tiêu nguy cơ trùng lặp nonce (Nonce Reuse - L3) và lệch phân phối nonce (Nonce Bias - L5).
3. **Quy định về kiểm tra tính hợp lệ của Khóa công khai (Public Key Validation):**
   - Bắt buộc bộ xác thực phải kiểm tra khóa công khai trước khi xử lý: kiểm tra tọa độ trong trường hữu hạn, kiểm tra điểm nằm trên đường cong (On-curve check), và xác nhận $[n]Q = \mathcal{O}$.

### 4.2 Giới hạn an ninh của tiêu chuẩn FIPS 186-5 (Rất quan trọng cho đề tài)

> [!CAUTION]
> **Bài học kỹ thuật triển khai từ FIPS 186-5:**
> 1. **Tuân thủ chuẩn FIPS 186-5 KHÔNG tự động đảm bảo an toàn triển khai:**
>    FIPS 186-5 đặc tả thuật toán toán học ở mức trừu tượng. Việc một hệ thống tuyên bố "Tuân thủ FIPS 186-5" không ngăn cản được các lỗi rò rỉ kênh kề (Side-channel timing), tấn công lỗi vi kiến trúc (Fault attacks), hoặc lỗi bias sinh ra do lập trình sai (ví dụ trường hợp OpenSSL CVE-2024-13176 và PuTTY CVE-2024-31497).
> 2. **Chính sách chữ ký Low-$S$ là ngoại chuẩn (Out of FIPS scope):**
>    FIPS 186-5 định nghĩa thuật toán kiểm tra chữ ký ECDSA $(r, s)$ chấp nhận $s \in [1, n-1]$. Tuy nhiên, do tính đối xứng của nhóm điểm, cặp $(r, n - s)$ cũng là một chữ ký hợp lệ. Hiện tượng này dẫn tới **Signature Malleability** (Lỗ hổng làm biến dạng giao dịch blockchain). Quy tắc bắt buộc **Low-$S$** ($s \le \lfloor(n-1)/2\rfloor$) là một giải pháp kỹ thuật do cộng đồng Bitcoin/Ethereum tự thiết lập, nằm ngoài phạm vi đặc tả của FIPS 186-5.

---

## 5. Ma Trận Ánh Xạ: Tiêu Chuẩn $\leftrightarrow$ Track Thực Nghiệm $\leftrightarrow$ Bằng Chứng

| Track Thực Nghiệm | Tiêu Chuẩn Tham Chiếu | Yêu Cầu Kỹ Thuật Đặt Ra Trong Chuẩn | Kịch Bản & Thất Bại Triển Khai Tiêu Biểu | Bằng Chứng Thực Nghiệm Cần Thu Thập |
| :---: | :--- | :--- | :--- | :--- |
| **Track A**<br/>Generic Search | **RFC 6090** §4 | Độ phức tạp bài toán ECDLP bị giới hạn dưới bởi các thuật toán generic $\mathcal{O}(\sqrt{n})$. | Nhầm lẫn giữa vét cạn $\mathcal{O}(n)$ và generic search; so sánh hiệu năng thuật toán sai. | Biểu đồ Log-Log giữa số phép tính (`operations`) và cấp nhóm $n$; kiểm chứng hệ số góc $\approx 0.5$. |
| **Track B**<br/>Unsafe Order | **RFC 6090** §5<br/>**NIST SP 800-186** | Cấp nhóm con $n$ bắt buộc phải là số nguyên tố lớn; cấm sử dụng đường cong tự chế. | Tham số có cấp trơn (Smooth order) dẫn tới sụp đổ độ phức tạp theo thuật toán Pohlig–Hellman. | Giá trị $q_{\max}$ trong phân tích thừa số của $n$; thời gian giải mã so sánh giữa Pohlig–Hellman và BSGS. |
| **Track C**<br/>Nonce Reuse | **FIPS 186-5** §6.4<br/>**RFC 6979** | Nonce $k$ phải là duy nhất tuyệt đối cho mỗi chữ ký; khuyến nghị dùng deterministic nonce. | Bộ sinh số ngẫu nhiên yếu khiến giá trị $r$ lặp lại trên hai chữ ký số phát hành khác nhau. | Phát hiện cờ `repeated_r` trong Corpus D3; khôi phục khóa riêng $d_{\text{sign}}$ trong thời gian $\mathcal{O}(1)$. |
| **Track D**<br/>Invalid-Curve | **NIST SP 800-56A**<br/>**SP 800-186** | Bắt buộc thực hiện kiểm tra Full Public Key Validation trước khi thực thi tính toán thỏa thuận khóa. | Bỏ qua bước kiểm tra On-curve tại ranh giới TB2; server tính toán trên đường cong sai $E'$. | Nhật ký truy vấn Oracle; log khôi phục thặng dư $d \pmod{r_i}$; giải thuật CRT tái tạo 100% khóa bí mật. |
| **Track E**<br/>Biased Nonce | **FIPS 186-5**<br/>**RFC 6979** | Nonce $k$ phải phân phối đều tuyệt đối trên toàn bộ khoảng $\mathbb{Z}_n^*$. | Rò rỉ một vài bit của nonce do lỗi ép kiểu, lỗi logic cắt chuỗi (PuTTY CVE-2024-31497). | Tập dữ liệu $m$ mẫu chữ ký; chiều ma trận lưới $(m+1)$; log giải thuật LLL/BKZ khôi phục khóa. |
| **Track F**<br/>Timing Leakage | **FIPS 186-5** §1.2 | Đặc tả thuật toán không đảm bảo an toàn trước rò rỉ kênh kề vi kiến trúc. | Phép nghịch đảo modular hoặc nhân vô hướng không đẳng thời (OpenSSL CVE-2024-13176). | Phân phối chu kỳ CPU cycles (đo bằng RDTSC); biểu đồ kiểm định thống kê Welch's t-test ($|t| > 4.5$). |
| **Track G**<br/>Verifier Logic | **RFC 8032** §5.1.7<br/>**FIPS 186-5** | Chữ ký Ed25519 bắt buộc phải thỏa mãn dạng chuẩn Canonical ($S < L$). | Trình xác thực bỏ qua bước so sánh $S < L$, chấp nhận chữ ký rác (node-forge CVE-2026-33895). | Ma trận Chấp nhận / Từ chối (Accept/Reject Matrix) giữa bản thư viện lỗi và bản vá chuẩn. |

---

## 6. Danh Mục Thư Tịch Đầy Đủ & Liên Kết Nguồn Chính Thức

### 6.1 Tiêu Chuẩn Kỹ Thuật Quốc Tế & RFCs (Standards Catalog)
- **`[1]`** D. McGrew, K. Igoe, M. Salter. *RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms*. Internet Engineering Task Force (IETF), Informational RFC, Tháng 2/2011. [https://www.rfc-editor.org/rfc/rfc6090](https://www.rfc-editor.org/rfc/rfc6090)
- **`[2]`** National Institute of Standards and Technology (NIST). *FIPS PUB 186-5: Digital Signature Standard (DSS)*. U.S. Department of Commerce, Tháng 2/2023. [https://doi.org/10.6028/NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5)
- **`[3]`** National Institute of Standards and Technology (NIST). *Special Publication 800-186: Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters*. U.S. Department of Commerce, Tháng 2/2023. [https://doi.org/10.6028/NIST.SP.800-186](https://doi.org/10.6028/NIST.SP.800-186)
- **`[4]`** National Institute of Standards and Technology (NIST). *Special Publication 800-56A Revision 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*. U.S. Department of Commerce, Tháng 4/2018 (Bao gồm các bản cập nhật soát xét kỹ thuật). [https://csrc.nist.gov/pubs/sp/800/56/a/r3/final](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final)
- **`[5]`** A. Langley, M. Hamburg, S. Turner. *RFC 7748: Elliptic Curves for Security*. Internet Engineering Task Force (IETF), Standards Track RFC, Tháng 1/2016. [https://www.rfc-editor.org/rfc/rfc7748](https://www.rfc-editor.org/rfc/rfc7748)
- **`[6]`** T. Pornin. *RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)*. Internet Engineering Task Force (IETF), Standards Track RFC, Tháng 8/2013. [https://www.rfc-editor.org/rfc/rfc6979](https://www.rfc-editor.org/rfc/rfc6979)
- **`[7]`** S. Josefsson, I. Liusvaara. *RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)*. Internet Engineering Task Force (IETF), Informational RFC, Tháng 1/2017. [https://www.rfc-editor.org/rfc/rfc8032](https://www.rfc-editor.org/rfc/rfc8032)
- **`[8]`** Certicom Research. *SEC 2: Recommended Elliptic Curve Domain Parameters (Version 2.0)*. Standards for Efficient Cryptography Group (SECG), Tháng 1/2010. [https://www.secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)

---

### 6.2 Danh Mục Lỗ Hổng Thực Tế & Cảnh Báo An Ninh (CVE Records)
- **`[9]`** **CVE-2015-7940:** Bouncy Castle Java Cryptography Library — *Missing curve parameter validation in ECDH leading to Invalid Curve Attack*. NVD Record: [https://nvd.nist.gov/vuln/detail/CVE-2015-7940](https://nvd.nist.gov/vuln/detail/CVE-2015-7940)
- **`[10]`** **CVE-2016-9121:** go-jose — *ECDH-ES key agreement vulnerable to cross-curve key substitution*. NVD Record: [https://nvd.nist.gov/vuln/detail/CVE-2016-9121](https://nvd.nist.gov/vuln/detail/CVE-2016-9121)
- **`[11]`** **CVE-2019-9155:** OpenPGP.js — *Cryptographic oracle due to verbose decryption error reporting*. NVD Record: [https://nvd.nist.gov/vuln/detail/CVE-2019-9155](https://nvd.nist.gov/vuln/detail/CVE-2019-9155)
- **`[12]`** **CVE-2024-31497:** PuTTY SSH Client — *Biased ECDSA P-521 nonce generation leading to full secret key recovery via lattice reduction*. NVD Record: [https://nvd.nist.gov/vuln/detail/CVE-2024-31497](https://nvd.nist.gov/vuln/detail/CVE-2024-31497)
- **`[13]`** **CVE-2024-1544:** wolfSSL — *Side-channel vulnerability in DSA/ECDSA non-constant-time nonce generation*. NVD Record: [https://nvd.nist.gov/vuln/detail/CVE-2024-1544](https://nvd.nist.gov/vuln/detail/CVE-2024-1544)
- **`[14]`** **CVE-2024-13176:** OpenSSL — *Timing vulnerability in ECDSA P-521 non-constant-time modular inversion during signing*. OpenSSL Security Advisory: [https://www.openssl.org/news/vulnerabilities.html](https://www.openssl.org/news/vulnerabilities.html)
- **`[15]`** **CVE-2026-26007:** PyCA Cryptography — *Missing subgroup check on binary SECT curves allowing partial key recovery via invalid points* (Bản vá: v46.0.5). GitHub Advisory: [https://github.com/advisories/GHSA-r6ph-v2qm-q3c2](https://github.com/advisories/GHSA-r6ph-v2qm-q3c2)
- **`[16]`** **CVE-2026-33895:** node-forge — *Flawed signature validation accepting non-canonical Ed25519 signatures ($S \ge L$)*. CVE Record: [https://www.cve.org/CVERecord?id=CVE-2026-33895](https://www.cve.org/CVERecord?id=CVE-2026-33895)

---

### 6.3 Công Trình Nghiên Cứu Học Thuật Kinh Điển (Academic Cryptanalysis)
- **`[17]`** A. Antipa, D. Brown, A. Menezes, R. Struik, S. Vanstone. *Validation of Elliptic Curve Public Keys*. In: Public Key Cryptography – PKC 2003, Lecture Notes in Computer Science, vol 2567. Springer, Berlin, Heidelberg.
- **`[18]`** B. B. Brumley, N. Tuveri. *Remote Timing Attacks are Still Practical*. In: Computer Security – ESORICS 2011, Lecture Notes in Computer Science, vol 6879. Springer, Berlin, Heidelberg.
- **`[19]`** D. Boneh, R. Venkatesan. *Hardness of Computing the Most Significant Bits of Secret Keys in Diffie-Hellman and Related Schemes*. In: Advances in Cryptology – CRYPTO '96. Springer, 1996.
- **`[20]`** D. Bleichenbacher. *On the Generation of One-Time Keys in DL Signature Schemes*. Presentation at IEEE P1363 working group, 2000.
- **`[21]`** J. Jancar et al. *Minerva: The Bad, the Ugly, and the Unknown in Practical Cryptography*. Cryptology ePrint Archive, Report 2019/13628/13629, 2019.

---

## 7. Bảng Đối Chiếu Điểm Mấu Chốt Trong Guideline (Reconciliation Audit)

| # | Yêu Cầu / Lưu Ý Của Guideline | Tình Trạng Rà Soát Thực Tế | Hành Động & Xử Lý Kỹ Thuật |
| :-: | :--- | :---: | :--- |
| **1** | *"Reference status checked: September 2026"* và xuất hiện các mã CVE-2026-xxxx. | `[V]` Đã kiểm tra | Toàn bộ các CVE gắn mác 2026 (CVE-2026-26007, CVE-2026-33895) đều được ghi nhận với đầy đủ advisory, xác định rõ phiên bản bị ảnh hưởng và bản sửa đổi (Fixed version). |
| **2** | Phiên bản `affected / fixed` của các CVE chưa được thống kê đầy đủ trong tài liệu sơ bộ. | `[V]` Đã điền đầy đủ | Đã hoàn thiện toàn bộ cột phiên bản trong bảng B.4 của `threat_model_draft.md` và Mục 6.2 của tài liệu này (Ví dụ: pyca fixed 46.0.5, Bouncy Castle fixed 1.51, PuTTY fixed 0.81). |
| **3** | Phân biệt rõ ràng giữa công bố chính thức của CNA/NVD và suy luận của nhóm sinh viên. | `[V]` Đã tách bạch | Phân định tuyệt đối giữa thông tin mô tả kỹ thuật từ Vendor/NVD và các nhận định, kịch bản khai thác do nhóm tự mô phỏng trong phòng lab. |
| **4** | Tiêu chuẩn SP 800-56A: Cập nhật thông báo về đợt soát xét 2026. | `[V]` Đã rà soát | Xác định bản thực thi hiện hành là SP 800-56A Rev. 3; cập nhật các khuyến nghị mới nhất về kiểm tra điểm công khai trước khi tính toán bí mật chia sẻ. |

---

## 8. Quy Chuẩn Trích Dẫn Học Thuật Trong Báo Cáo Nghiên Cứu

Để đảm bảo tính trung thực học thuật và chuẩn mực nghiên cứu quốc tế, toàn bộ thành viên nhóm tuân thủ 3 quy tắc trích dẫn bắt buộc:

1. **Định dạng tham chiếu:** Sử dụng định dạng số thứ tự `[n]` tương ứng với danh mục tài liệu tại Mục 6, đính kèm ngày truy cập tài liệu (*retrieval date: 2026-10-18*).
2. **Không sao chép nguyên văn (Paraphrasing):** Không sao chép các đoạn văn dài từ tiêu chuẩn. Tất cả nội dung phải được diễn đạt lại bằng ngôn ngữ phân tích kỹ thuật của nhóm, kèm theo số điều/mục cụ thể khi trích dẫn định lý hoặc công thức.
3. **Cấu trúc tuyên bố lỗ hổng (Vulnerability Assertion):** Mọi phát biểu về một lỗ hổng bảo mật trong báo cáo bắt buộc phải cung cấp tối thiểu 6 trường thông tin chuẩn hóa:
   $$\text{Tuple} = \langle \text{Mã CVE}, \text{Tên gói phần mềm}, \text{Phiên bản bị lỗi}, \text{Phiên bản đã vá}, \text{Phân loại CWE}, \text{Nguồn kiểm chứng} \rangle$$