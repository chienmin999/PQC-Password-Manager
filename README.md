# PQC Password Manager -- ML-KEM-768

## 1. Giới thiệu

Đây là chương trình mô phỏng hệ thống **quản lý mật khẩu an toàn sử dụng
thuật toán mật mã hậu lượng tử ML-KEM**.

Mô hình triển khai:

``` text
                    +-----------------------------+
                    |       WINDOWS SERVER        |
                    | Flask REST API + SQLite     |
                    |                             |
                    | User / Device / Vault       |
                    | Wrapped Vault Key           |
                    +--------------+--------------+
                                   |
                    +--------------+--------------+
                    |                             |
             +------v------+               +------v------+
             |  UBUNTU 1   |               |  UBUNTU 2   |
             |   Client    |               |   Client    |
             | ML-KEM-768  |               | ML-KEM-768  |
             +-------------+               +-------------+
```

Server lưu **Vault đã mã hóa** và các bản **K_VAULT được bảo vệ cho từng
thiết bị**.

Nội dung Vault được mã hóa bằng **AES-256-GCM**. ML-KEM-768 được sử dụng
để thực hiện `KeyGen()`, `Encaps()` và `Decaps()` nhằm thiết lập bí mật
chung và bảo vệ khóa `K_VAULT`.

------------------------------------------------------------------------

# 2. Kiến trúc mật mã

## 2.1. K_VAULT

Mỗi Vault có một khóa đối xứng riêng:

``` text
K_VAULT = 32 bytes
```

Dữ liệu Vault:

``` text
Vault plaintext
       |
       v
AES-256-GCM(K_VAULT)
       |
       v
Encrypted Vault
```

ML-KEM **không mã hóa trực tiếp toàn bộ Vault**.

## 2.2. Bảo vệ K_VAULT cho từng thiết bị

Thiết bị đích có cặp khóa ML-KEM-768:

``` text
Public Key
Secret Key
```

Thiết bị cấp quyền thực hiện:

``` text
(CT, SS) = ML-KEM.Encaps(PublicKey_Device)

K_wrap = HKDF-SHA256(SS)

Wrapped_K_VAULT =
    AES-256-GCM(K_wrap, K_VAULT)
```

Server lưu:

``` text
Encrypted Vault
KEM Ciphertext
Wrapped K_VAULT
Nonce
```

Server **không lưu K_VAULT dạng rõ**.

Thiết bị đích thực hiện:

``` text
SS = ML-KEM.Decaps(SecretKey, CT)

K_wrap = HKDF-SHA256(SS)

K_VAULT =
    AES-256-GCM-Decrypt(K_wrap, Wrapped_K_VAULT)
```

Sau đó dùng `K_VAULT` để giải mã Vault.

------------------------------------------------------------------------

# 3. Yêu cầu hệ thống

## 3.1. Windows Server

Môi trường đã kiểm thử:

``` text
Project:
D:\PQC\PQC-Password-Manager

liboqs source:
D:\PQC\liboqs

liboqs install:
D:\PQC\liboqs-install

Python:
C:\Python314\python.exe
```

Cần có Python, CMake và môi trường build phù hợp nếu tự biên dịch
liboqs.

## 3.2. Ubuntu Client

Môi trường đã kiểm thử:

``` text
Ubuntu 22.04.2 LTS
Python 3.10.6
GCC 11.4
CMake 3.22.1
Git 2.34.1
```

Project:

``` text
~/PQC/PQC-Password-Manager
```

liboqs:

``` text
~/PQC/liboqs
```

liboqs install:

``` text
~/PQC/liboqs-install
```

------------------------------------------------------------------------

# 4. Cấu trúc thư mục

``` text
PQC-Password-Manager/
|
+-- app/
|   +-- main.py
|   +-- login_window.py
|   +-- vault_window.py
|   +-- mlkem_manager.py
|   +-- vault_key_crypto.py
|   +-- secure_storage.py
|   +-- device_crypto.py
|   +-- server_client.py
|   +-- ...
|
+-- server/
|   +-- server.py
|   +-- database.py
|   +-- ...
|
+-- common/
|   +-- mlkem_manager.py
|   +-- crypto_utils.py
|   +-- ...
|
+-- data/
|   +-- device_config.json
|   +-- device2_config.json
|   +-- vault_config.json
|
+-- .venv/
|
+-- README.md
```

------------------------------------------------------------------------

# 5. CÀI LIBOQS TRÊN WINDOWS

Mở PowerShell:

``` powershell
cd D:\PQC
```

Clone:

``` powershell
git clone https://github.com/open-quantum-safe/liboqs.git
```

Build chỉ ML-KEM-768:

``` powershell
cmake -S D:\PQC\liboqs `
      -B D:\PQC\liboqsuild `
      -DBUILD_SHARED_LIBS=ON `
      -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE `
      -DOQS_BUILD_ONLY_LIB=ON `
      -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 `
      -DCMAKE_INSTALL_PREFIX=D:\PQC\liboqs-install
```

Build:

``` powershell
cmake --build D:\PQC\liboqsuild --config Release
```

Install:

``` powershell
cmake --install D:\PQC\liboqsuild --config Release
```

Kiểm tra:

``` powershell
dir D:\PQC\liboqs-installin\oqs.dll
```

Phải có:

``` text
D:\PQC\liboqs-installin\oqs.dll
```

------------------------------------------------------------------------

# 6. TẠO PYTHON VENV TRÊN WINDOWS

``` powershell
cd D:\PQC\PQC-Password-Manager
```

``` powershell
C:\Python314\python.exe -m venv .venv
```

Kích hoạt:

``` powershell
.\.venv\Scripts\Activate.ps1
```

Kết quả:

``` text
(.venv) PS D:\PQC\PQC-Password-Manager>
```

**Không chỉnh sửa `Activate.ps1` để thêm biến môi trường.**

------------------------------------------------------------------------

# 7. CẤU HÌNH LIBOQS TRÊN WINDOWS

Mỗi PowerShell mới:

``` powershell
$env:OQS_INSTALL_PATH = "D:\PQC\liboqs-install"
$env:PATH = "D:\PQC\liboqs-installin;$env:PATH"
```

Kiểm tra:

``` powershell
python -c "import oqs; print(oqs.get_enabled_KEM_mechanisms())"
```

Kết quả mong đợi:

``` text
('ML-KEM-768',)
```

------------------------------------------------------------------------

# 8. CÀI PYTHON PACKAGES TRÊN WINDOWS

Nếu có `requirements.txt`:

``` powershell
pip install -r requirements.txt
```

Hoặc:

``` powershell
pip install liboqs-python cryptography requests Flask PySide6
```

------------------------------------------------------------------------

# 9. CÀI UBUNTU CLIENT

``` bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git cmake build-essential
```

Kiểm tra:

``` bash
python3 --version
gcc --version
cmake --version
```

------------------------------------------------------------------------

# 10. TẠO VENV TRÊN UBUNTU

``` bash
cd ~/PQC/PQC-Password-Manager
```

``` bash
python3 -m venv .venv
```

``` bash
source .venv/bin/activate
```

------------------------------------------------------------------------

# 11. CẤU HÌNH LIBOQS TRÊN UBUNTU

``` bash
export OQS_INSTALL_PATH="$HOME/PQC/liboqs-install"
export LD_LIBRARY_PATH="$HOME/PQC/liboqs-install/lib:$LD_LIBRARY_PATH"
```

Kiểm tra:

``` bash
python -c "import oqs; print(oqs.get_enabled_KEM_mechanisms())"
```

Kết quả:

``` text
('ML-KEM-768',)
```

Cài package:

``` bash
pip install liboqs-python cryptography requests Flask PySide6
```

------------------------------------------------------------------------

# 12. KIỂM TRA ML-KEM

Chạy:

``` bash
python test_mlkem.py
```

Kết quả cần xác nhận:

``` text
ML-KEM-768
Public Key: 1184 bytes
Secret Key: 2400 bytes
Ciphertext: 1088 bytes
Shared Secret: 32 bytes
Shared Secret Match: SUCCESS
```

------------------------------------------------------------------------

# 13. CẤU HÌNH IP SERVER

Trên Windows Server:

``` powershell
ipconfig
```

Lấy:

``` text
IPv4 Address
```

Ví dụ:

``` text
192.168.202.133
```

**Không giả định IP luôn cố định.** Nếu Windows dùng DHCP, IP có thể
thay đổi sau khi reboot.

Trên Client, `base_url` phải trỏ tới IP hiện tại:

``` json
"server": {
    "base_url": "http://192.168.202.133:8000"
}
```

Device 1:

``` text
data/device_config.json
```

Device 2:

``` text
data/device2_config.json
```

------------------------------------------------------------------------

# 14. KIỂM TRA CLIENT → SERVER

Sau khi Server chạy:

``` bash
curl http://192.168.202.133:8000/api/health
```

Kết quả:

``` json
{"status":"ok"}
```

Nếu không kết nối được, kiểm tra:

1.  Windows Server đã chạy chưa.
2.  IP Server có đúng không.
3.  Windows Firewall.
4.  Hai máy có cùng mạng nội bộ/VM network hay không.
5.  Port 8000 có đang lắng nghe hay không.

------------------------------------------------------------------------

# 15. KHỞI ĐỘNG SERVER TRÊN WINDOWS

Mở PowerShell:

``` powershell
cd D:\PQC\PQC-Password-Manager
```

``` powershell
.\.venv\Scripts\Activate.ps1
```

``` powershell
$env:OQS_INSTALL_PATH = "D:\PQC\liboqs-install"
$env:PATH = "D:\PQC\liboqs-installin;$env:PATH"
```

Chạy:

``` powershell
python -m server.server
```

Phải thấy:

``` text
* Running on all addresses (0.0.0.0)
* Running on http://127.0.0.1:8000
* Running on http://IP_SERVER:8000
```

Giữ nguyên cửa sổ PowerShell này.

Kiểm tra bằng cửa sổ khác:

``` powershell
curl http://127.0.0.1:8000/api/health
```

Kết quả:

``` json
{"status":"ok"}
```

------------------------------------------------------------------------

# 16. KHỞI ĐỘNG GUI CLIENT

Trên Ubuntu:

``` bash
cd ~/PQC/PQC-Password-Manager
source .venv/bin/activate
export OQS_INSTALL_PATH="$HOME/PQC/liboqs-install"
export LD_LIBRARY_PATH="$HOME/PQC/liboqs-install/lib:$LD_LIBRARY_PATH"
python -m app.main
```

Không chạy `server.server` trên Ubuntu Client.

------------------------------------------------------------------------

# 17. CHẠY HAI CLIENT

Client 1:

``` bash
cd ~/PQC/PQC-Password-Manager
source .venv/bin/activate
export OQS_INSTALL_PATH="$HOME/PQC/liboqs-install"
export LD_LIBRARY_PATH="$HOME/PQC/liboqs-install/lib:$LD_LIBRARY_PATH"
python -m app.main
```

Client 2 thực hiện tương tự.

Hai Client có:

``` text
User ID giống nhau
Vault giống nhau
Device ID khác nhau
ML-KEM key pair khác nhau
```

------------------------------------------------------------------------

# 18. ĐĂNG NHẬP

Device 1 dùng:

``` text
data/device_config.json
```

Device 2 dùng:

``` text
data/device2_config.json
```

Nhập Master Password.

Các chức năng chính:

``` text
+ Add Password
Edit
Delete
Generate Password
Sync to Server
Download / Sync
Lock Vault
```

------------------------------------------------------------------------

# 19. ĐỒNG BỘ VAULT

## Client 1

Thêm mật khẩu:

``` text
Add Password
```

Sau đó:

``` text
Sync to Server
```

## Client 2

Chọn:

``` text
Download / Sync
```

Client 2 thực hiện:

``` text
Get Encrypted Vault
        |
Get Wrapped K_VAULT
        |
ML-KEM Decaps
        |
HKDF
        |
Recover K_VAULT
        |
AES-256-GCM
        |
Vault
```

------------------------------------------------------------------------

# 20. ĐỒNG BỘ NGƯỢC

Client 2:

``` text
Add / Edit / Delete
```

Sau đó:

``` text
Sync to Server
```

Client 1:

``` text
Download / Sync
```

Kiểm tra dữ liệu thay đổi.

------------------------------------------------------------------------

# 21. KIỂM TRA VERSION CONFLICT

Giả sử:

``` text
Client 1 = version 10
Client 2 = version 10
Server   = version 10
```

Client 1:

``` text
Edit
Sync to Server
```

Server tăng:

``` text
10 -> 11
```

Client 2 vẫn có:

``` text
base_version = 10
```

Client 2 cố Sync:

``` text
HTTP 409
```

GUI hiển thị:

``` text
Version Conflict

Vault trên Server đã được thiết bị khác cập nhật.

Hãy dùng Download / Sync để lấy phiên bản mới trước.
```

Đây là hành vi đúng.

------------------------------------------------------------------------

# 22. CÁC BÀI KIỂM THỬ

Phiên bản đã thực nghiệm các nhóm:

``` text
1. ML-KEM KeyGen
2. ML-KEM Encaps
3. ML-KEM Decaps
4. Shared Secret Match
5. Server KEM Exchange
6. K_VAULT Wrap
7. K_VAULT Unwrap
8. Vault Encryption
9. Vault Decryption
10. Multi-Device Vault
11. Version Increment
12. Version Conflict
13. Secret Key Protection
14. Wrong Password
15. Tampered Data
```

Kết quả tổng hợp của các kiểm thử chính:

``` text
11/11 PASS
```

------------------------------------------------------------------------

# 23. THÔNG SỐ ML-KEM-768

``` text
Algorithm:
ML-KEM-768

Security Category:
NIST Category 3

Public Key:
1184 bytes

Secret Key:
2400 bytes

Ciphertext:
1088 bytes

Shared Secret:
32 bytes
```

------------------------------------------------------------------------

# 24. THÔNG SỐ BẢO VỆ SECRET KEY

``` text
Scrypt
N = 2^14
r = 8
p = 1

Salt = 16 bytes
AES-GCM Nonce = 12 bytes
AES Key = 32 bytes
```

------------------------------------------------------------------------

# 25. THÔNG SỐ VAULT

``` text
AES-256-GCM
K_VAULT = 32 bytes
Nonce = 12 bytes
```

Wrapped K_VAULT:

``` text
AES-256-GCM
Plaintext = 32 bytes
Authentication Tag = 16 bytes
Ciphertext = 48 bytes
```

------------------------------------------------------------------------

# 26. HKDF

``` text
HKDF-SHA256
Input = ML-KEM Shared Secret
Output = 32 bytes
```

Thông tin sử dụng cho Vault Key:

``` text
PQC-Password-Manager-Vault-Key-Wrap
```

------------------------------------------------------------------------

# 27. FILE CẤU HÌNH

## Device 1

``` text
data/device_config.json
```

Chứa thông tin thiết bị, User ID, Device ID, public key và thông tin
Server.

## Device 2

``` text
data/device2_config.json
```

Chứa thông tin Device 2 và secret key đã được bảo vệ.

## Vault

``` text
data/vault_config.json
```

Chứa dữ liệu Vault đã mã hóa và thông tin bảo vệ K_VAULT.

K_VAULT không được lưu dạng rõ.

------------------------------------------------------------------------

# 28. SERVER DATABASE

Server sử dụng:

``` text
server/server.db
```

Đây là SQLite database.

Có thể sao lưu file này khi Server đã dừng.

Không nên chỉnh sửa trực tiếp database khi Server đang chạy.

------------------------------------------------------------------------

# 29. SAU KHI WINDOWS REBOOT

Mỗi lần Windows khởi động lại:

### 1. Kiểm tra IP

``` powershell
ipconfig
```

### 2. Vào project

``` powershell
cd D:\PQC\PQC-Password-Manager
```

### 3. Kích hoạt venv

``` powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Cấu hình liboqs

``` powershell
$env:OQS_INSTALL_PATH = "D:\PQC\liboqs-install"
$env:PATH = "D:\PQC\liboqs-installin;$env:PATH"
```

### 5. Chạy Server

``` powershell
python -m server.server
```

### 6. Nếu IP đổi

Cập nhật:

``` text
data/device_config.json
data/device2_config.json
```

trên các Client.

------------------------------------------------------------------------

# 30. KHÔNG CHẠY SERVER TRÊN CLIENT

Mô hình đúng:

``` text
Ubuntu Client 1 --------+
                        |
                        v
                 Windows Server
                    Port 8000
                        ^
                        |
Ubuntu Client 2 --------+
```

Ubuntu Client chỉ chạy:

``` bash
python -m app.main
```

Windows Server chạy:

``` powershell
python -m server.server
```

------------------------------------------------------------------------

# 31. KHẮC PHỤC LỖI THƯỜNG GẶP

## Không import được oqs

``` bash
python -c "import oqs; print(oqs.get_enabled_KEM_mechanisms())"
```

Nếu thiếu:

``` bash
pip install liboqs-python
```

## Windows không tìm thấy oqs.dll

``` powershell
dir D:\PQC\liboqs-installin\oqs.dll
```

Sau đó:

``` powershell
$env:OQS_INSTALL_PATH = "D:\PQC\liboqs-install"
$env:PATH = "D:\PQC\liboqs-installin;$env:PATH"
```

## Ubuntu không tìm thấy liboqs.so

``` bash
export OQS_INSTALL_PATH="$HOME/PQC/liboqs-install"
export LD_LIBRARY_PATH="$HOME/PQC/liboqs-install/lib:$LD_LIBRARY_PATH"
```

## Client không kết nối Server

``` bash
curl http://IP_SERVER:8000/api/health
```

Nếu lỗi timeout, kiểm tra IP, firewall, mạng VM và port 8000.

## Vẫn kết nối tới IP cũ

Tìm:

``` bash
grep -R "192.168.198.1" app/
```

Windows:

``` powershell
Get-ChildItem -Recurse -File | Select-String "192.168.198.1"
```

## Version Conflict

Không xóa Vault.

Chọn:

``` text
Download / Sync
```

sau đó mới chỉnh sửa và Sync lại.

------------------------------------------------------------------------

# 32. GIỚI HẠN CỦA PHIÊN BẢN MÔ PHỎNG

Đây là phiên bản phục vụ nghiên cứu/đồ án, chưa phải hệ thống
production.

Các giới hạn:

1.  Xác thực User chưa hoàn chỉnh.
2.  Phân quyền Device còn đơn giản.
3.  Chưa có cơ chế thu hồi thiết bị hoàn chỉnh.
4.  Server đang dùng Flask development server.
5.  Chưa triển khai HTTPS.
6.  Chưa có merge conflict chi tiết.
7.  Client bị kiểm soát hoàn toàn khi Vault đang mở có thể làm lộ
    K_VAULT trong bộ nhớ.
8.  Cần cơ chế bảo vệ Secret Key tốt hơn khi triển khai thực tế.

------------------------------------------------------------------------

# 33. THÔNG TIN ĐỀ TÀI

**Tên đề tài:**

> Nghiên cứu, đề xuất giải pháp quản lý mật khẩu an toàn sử dụng thuật
> toán mật mã hậu lượng tử ML-KEM

**Thuật toán chính:**

``` text
ML-KEM-768
```

**Mã hóa dữ liệu:**

``` text
AES-256-GCM
```

**Dẫn xuất khóa:**

``` text
HKDF-SHA256
```

**Bảo vệ Secret Key cục bộ:**

``` text
Scrypt + AES-256-GCM
```

**Server:**

``` text
Flask + SQLite
```

**Client GUI:**

``` text
Python + PySide6
```

**PQC implementation:**

``` text
liboqs + liboqs-python
```

------------------------------------------------------------------------

# 34. QUICK START

## Windows Server

``` powershell
cd D:\PQC\PQC-Password-Manager
.\.venv\Scripts\Activate.ps1
$env:OQS_INSTALL_PATH = "D:\PQC\liboqs-install"
$env:PATH = "D:\PQC\liboqs-installin;$env:PATH"
python -m server.server
```

## Ubuntu Client

``` bash
cd ~/PQC/PQC-Password-Manager
source .venv/bin/activate
export OQS_INSTALL_PATH="$HOME/PQC/liboqs-install"
export LD_LIBRARY_PATH="$HOME/PQC/liboqs-install/lib:$LD_LIBRARY_PATH"
python -m app.main
```

Sau đó:

``` text
Login
  |
Open Vault
  |
Add / Edit / Delete
  |
Sync to Server
  |
Download / Sync trên Client còn lại
```

------------------------------------------------------------------------

# 35. GHI CHÚ PHIÊN BẢN

Môi trường đã kiểm thử:

``` text
ML-KEM-768
Windows Server
Ubuntu 22.04.2 LTS Client 1
Ubuntu 22.04.2 LTS Client 2
Python
liboqs
liboqs-python
Flask
SQLite
PySide6
AES-256-GCM
HKDF-SHA256
Scrypt
```

README này dùng làm tài liệu cài đặt và vận hành cho bộ source của
chương trình mô phỏng.
