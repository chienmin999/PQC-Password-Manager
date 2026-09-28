# gui.py
# Giao dien desktop cho PQC Password Manager
# Kien truc:
#   Master password
#       -> Scrypt
#       -> bao ve ML-KEM secret key
#   ML-KEM-768
#       -> shared secret
#       -> HKDF-SHA256
#       -> AES-256-GCM
#       -> ma hoa kho mat khau
#
# Yeu cau:
#   - Python 3.x
#   - Tkinter (thuong da co san tren Windows)
#   - cac file hien co: vault.py, vault_crypto.py, storage.py, liboqs-python

import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox

from vault import PasswordVault
from vault_crypto import SecureVault
from storage import load_vault, save_vault

import base64
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CAU HINH GIAO DIEN
# ============================================================

APP_TITLE = "Trình quản lý mật khẩu PQC"
WINDOW_SIZE = "1180x760"
MIN_WIDTH = 1000
MIN_HEIGHT = 650

FONT = "Segoe UI"

BG = "#0f172a"
SIDEBAR = "#111827"
CARD = "#1e293b"
CARD_2 = "#243244"
INPUT = "#0b1220"
BORDER = "#334155"
TEXT = "#f8fafc"
TEXT_MUTED = "#94a3b8"
ACCENT = "#38bdf8"
ACCENT_HOVER = "#0ea5e9"
GREEN = "#34d399"
RED = "#fb7185"
YELLOW = "#fbbf24"


# ============================================================
# CAC HAM TIEN ICH
# ============================================================

def generate_password(length=20):
    """Tao mat khau ngau nhien manh bang secrets."""
    if length < 12:
        length = 12

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+[]{};:,.?",
    ]

    chars = [
        secrets.choice(group)
        for group in groups
    ]

    all_chars = "".join(groups)

    while len(chars) < length:
        chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def mask_password(password):
    if not password:
        return ""
    return "•" * min(max(len(password), 8), 24)


def safe_call_create(secure, vault, master_password):
    """
    Goi create_vault theo API hien tai cua project.
    Ho tro them mot vai dang goi pho bien de GUI khong bi
    phu thuoc cung cung mot cach dat thu tu tham so.
    """
    try:
        return secure.create_vault(vault, master_password)
    except TypeError as first_error:
        try:
            return secure.create_vault(master_password, vault)
        except TypeError:
            raise first_error


def safe_call_decrypt(secure, encrypted_vault, master_password, vault):
    try:
        return secure.decrypt_vault(encrypted_vault, master_password, vault)
    except TypeError as first_error:
        try:
            return secure.decrypt_vault(master_password, encrypted_vault, vault)
        except TypeError:
            try:
                return secure.decrypt_vault(encrypted_vault, vault, master_password)
            except TypeError:
                raise first_error


def safe_call_encrypt_existing(secure, encrypted_vault, vault, master_password):
    try:
        return secure.encrypt_existing_vault(
            encrypted_vault, vault, master_password
        )
    except TypeError as first_error:
        try:
            return secure.encrypt_existing_vault(
                vault, encrypted_vault, master_password
            )
        except TypeError:
            try:
                return secure.encrypt_existing_vault(
                    encrypted_vault, master_password, vault
                )
            except TypeError:
                raise first_error


# ============================================================
# HÀM HỖ TRỢ ĐỔI MẬT KHẨU CHỦ
# ============================================================

# Các tham số này phải khớp với vault_crypto.py V2 của dự án.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SECRET_KEY_AAD = b"PQC-Password-Manager:ML-KEM-SecretKey:v2"


def derive_master_key_gui(master_password, salt):
    """Tạo khóa bảo vệ khóa bí mật ML-KEM từ mật khẩu chủ."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(master_password.encode("utf-8"))


def restore_secret_key_gui(protected_data, master_password):
    """
    Giải mã khóa bí mật ML-KEM từ cấu trúc protected_secret_key V2.
    Không cần import protect/restore từ vault_crypto.py vì hai hàm đó
    không phải API cấp module trong phiên bản hiện tại.
    """
    try:
        salt = base64.b64decode(protected_data["salt"])
        nonce = base64.b64decode(protected_data["nonce"])
        encrypted_secret_key = base64.b64decode(
            protected_data["encrypted_secret_key"]
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise RuntimeError(
            "Dữ liệu bảo vệ khóa bí mật không hợp lệ."
        ) from exc

    master_key = derive_master_key_gui(master_password, salt)

    try:
        return AESGCM(master_key).decrypt(
            nonce,
            encrypted_secret_key,
            SECRET_KEY_AAD,
        )
    except Exception as exc:
        raise RuntimeError(
            "Không thể giải mã khóa bí mật ML-KEM bằng mật khẩu chủ."
        ) from exc


def protect_secret_key_gui(secret_key, master_password):
    """Bảo vệ lại khóa bí mật ML-KEM bằng mật khẩu chủ mới."""
    salt = os.urandom(16)
    nonce = os.urandom(12)

    master_key = derive_master_key_gui(master_password, salt)

    encrypted_secret_key = AESGCM(master_key).encrypt(
        nonce,
        secret_key,
        SECRET_KEY_AAD,
    )

    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "encrypted_secret_key": base64.b64encode(
            encrypted_secret_key
        ).decode("ascii"),
    }


# ============================================================
# STYLE
# ============================================================

def setup_style(root):
    style = ttk.Style(root)

    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        ".",
        font=(FONT, 10),
        background=BG,
        foreground=TEXT,
    )

    style.configure(
        "Treeview",
        background=CARD,
        foreground=TEXT,
        fieldbackground=CARD,
        borderwidth=1,
        relief="solid",
        rowheight=46,
        font=(FONT, 10),
    )

    style.map(
        "Treeview",
        background=[("selected", "#075985")],
        foreground=[("selected", "#ffffff")],
    )

    style.configure(
        "Treeview.Heading",
        background=CARD_2,
        foreground=TEXT,
        relief="solid",
        borderwidth=1,
        font=(FONT, 9, "bold"),
        padding=(10, 12),
    )

    style.map(
        "Treeview.Heading",
        background=[("active", BORDER)],
    )

    style.configure(
        "TScrollbar",
        background=CARD_2,
        troughcolor=INPUT,
        bordercolor=INPUT,
        arrowcolor=TEXT_MUTED,
    )


def make_button(parent, text, command, primary=False, width=None):
    bg = ACCENT if primary else CARD_2
    fg = "#07111f" if primary else TEXT
    active = ACCENT_HOVER if primary else BORDER

    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=active,
        activeforeground="#ffffff",
        relief="flat",
        bd=0,
        cursor="hand2",
        font=(FONT, 10, "bold"),
        padx=16,
        pady=10,
    )

    if width:
        btn.config(width=width)

    return btn


def make_entry(parent, textvariable=None, show=None):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        show=show or "",
        bg=INPUT,
        fg=TEXT,
        insertbackground=TEXT,
        selectbackground="#0369a1",
        selectforeground="#ffffff",
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        font=(FONT, 10),
    )


def make_card(parent, padx=20, pady=18):
    frame = tk.Frame(
        parent,
        bg=CARD,
        highlightthickness=1,
        highlightbackground=BORDER,
        bd=0,
    )
    frame.pack(fill="both", expand=True, padx=padx, pady=pady)
    return frame


# ============================================================
# DIALOG THEM MAT KHAU
# ============================================================

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, confirm=False):
        super().__init__(parent)

        self.result = None
        self.confirm = confirm

        self.title(title)

        # Hộp thoại xác nhận mật khẩu mới cần thêm chiều cao.
        # Đặt kích thước rộng/rộng hơn để không bị cắt nút hoặc ô nhập
        # trên Windows khi tỷ lệ hiển thị (DPI) > 100%.
        if confirm:
            self.geometry("520x340")
            self.minsize(520, 340)
        else:
            self.geometry("520x270")
            self.minsize(520, 270)

        self.resizable(True, True)
        self.configure(bg=BG)
        self.transient(parent)
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=28, pady=24)

        tk.Label(
            container,
            text=title,
            bg=BG,
            fg=TEXT,
            font=(FONT, 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            container,
            text=prompt,
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 10),
            justify="left",
            wraplength=450,
        ).pack(anchor="w", fill="x", pady=(6, 18))

        self.password_var = tk.StringVar()

        self.password_entry = make_entry(
            container,
            self.password_var,
            show="•",
        )
        self.password_entry.pack(fill="x", ipady=9)

        self.confirm_var = tk.StringVar()

        if confirm:
            tk.Label(
                container,
                text="Nhập lại mật khẩu",
                bg=BG,
                fg=TEXT_MUTED,
                font=(FONT, 9),
            ).pack(anchor="w", pady=(12, 5))

            self.confirm_entry = make_entry(
                container,
                self.confirm_var,
                show="•",
            )
            self.confirm_entry.pack(fill="x", ipady=9)

        buttons = tk.Frame(container, bg=BG)
        buttons.pack(fill="x", pady=(24, 0))

        make_button(
            buttons,
            "Hủy",
            self.cancel,
        ).pack(side="right", padx=(8, 0))

        make_button(
            buttons,
            "Tiếp tục",
            self.ok,
            primary=True,
        ).pack(side="right")

        self.password_entry.focus_set()
        self.bind("<Return>", lambda e: self.ok())
        self.bind("<Escape>", lambda e: self.cancel())

        self.wait_window(self)

    def ok(self):
        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "Thiếu mật khẩu",
                "Vui lòng nhập mật khẩu.",
                parent=self,
            )
            return

        if self.confirm and password != self.confirm_var.get():
            messagebox.showerror(
                "Không khớp",
                "Hai mật khẩu không giống nhau.",
                parent=self,
            )
            return

        self.result = password
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


# ============================================================
# DIALOG THEM / SUA TAI KHOAN
# ============================================================

class EntryDialog(tk.Toplevel):
    def __init__(self, parent, entry=None):
        super().__init__(parent)

        self.result = None
        self.editing = entry is not None

        self.title("Sửa tài khoản" if self.editing else "Thêm tài khoản")
        # Dialog truoc day cao 520px nen tren mot so man hinh/DPI
        # phan nut Luu/Huy bi nam ngoai cua so.
        self.geometry("620x650")
        self.minsize(620, 650)
        self.resizable(False, False)
        self.configure(bg=BG)
        self.transient(parent)
        self.grab_set()

        # Canh giua dialog theo cua so cha.
        self.update_idletasks()
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        dw = self.winfo_width()
        dh = self.winfo_height()
        x = px + max(0, (pw - dw) // 2)
        y = py + max(0, (ph - dh) // 2)
        self.geometry(f"{dw}x{dh}+{x}+{y}")

        self.service_var = tk.StringVar(
            value=entry.get("service", "") if entry else ""
        )
        self.username_var = tk.StringVar(
            value=entry.get("username", "") if entry else ""
        )
        self.password_var = tk.StringVar(
            value=entry.get("password", "") if entry else ""
        )

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=30, pady=26)

        tk.Label(
            container,
            text="Sửa tài khoản" if self.editing else "Thêm tài khoản",
            bg=BG,
            fg=TEXT,
            font=(FONT, 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            container,
            text=(
                "Cập nhật thông tin đăng nhập trong kho mật khẩu."
                if self.editing
                else "Tạo một mục đăng nhập mới trong kho mật khẩu."
            ),
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 10),
        ).pack(anchor="w", pady=(5, 22))

        self._field(container, "Dịch vụ / Website", self.service_var)
        self._field(container, "Tên đăng nhập / Email", self.username_var)

        # Password
        tk.Label(
            container,
            text="Mật khẩu",
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(14, 6))

        pw_row = tk.Frame(container, bg=BG)
        pw_row.pack(fill="x")

        self.password_entry = make_entry(
            pw_row,
            self.password_var,
            show="•",
        )
        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=9,
        )

        self.show_password = False

        make_button(
            pw_row,
            "Hiện",
            self.toggle_password,
        ).pack(side="left", padx=(8, 0))

        make_button(
            pw_row,
            "Tạo",
            self.generate,
            primary=True,
        ).pack(side="left", padx=(8, 0))

        # Note
        tk.Label(
            container,
            text="Ghi chú",
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(16, 6))

        self.note_text = tk.Text(
            container,
            height=4,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            selectbackground="#0369a1",
            selectforeground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
            font=(FONT, 10),
            wrap="word",
        )
        self.note_text.pack(fill="x")

        if entry:
            self.note_text.insert("1.0", entry.get("note", ""))

        buttons = tk.Frame(container, bg=BG)
        buttons.pack(fill="x", pady=(20, 0))

        make_button(
            buttons,
            "Hủy",
            self.cancel,
        ).pack(side="right", padx=(8, 0))

        make_button(
            buttons,
            "Lưu thay đổi" if self.editing else "Thêm tài khoản",
            self.ok,
            primary=True,
        ).pack(side="right")

        self.bind("<Escape>", lambda e: self.cancel())

        # RẤT QUAN TRỌNG:
        # Chờ hộp thoại đóng rồi mới trả quyền điều khiển về add_entry().
        # Trước đây EntryDialog không có wait_window(), nên add_entry()
        # chạy tiếp ngay lập tức, thấy self.result = None và thoát.
        # Vì vậy người dùng nhập xong bấm "Thêm tài khoản" nhưng tài khoản
        # không bao giờ được đưa vào danh sách.
        self.wait_window(self)

    def _field(self, parent, label, variable):
        tk.Label(
            parent,
            text=label,
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        entry = make_entry(parent, variable)
        entry.pack(fill="x", ipady=9)

    def generate(self):
        self.password_var.set(generate_password(20))
        self.show_password = True
        self.password_entry.config(show="")
        self.password_entry.select_range(0, "end")

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(
            show="" if self.show_password else "•"
        )

    def ok(self):
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        note = self.note_text.get("1.0", "end-1c").strip()

        if not service:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Vui lòng nhập tên dịch vụ / website.",
                parent=self,
            )
            return

        if not username:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Vui lòng nhập tên đăng nhập / email.",
                parent=self,
            )
            return

        if not password:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Vui lòng nhập mật khẩu.",
                parent=self,
            )
            return

        self.result = {
            "service": service,
            "username": username,
            "password": password,
            "note": note,
        }
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


# ============================================================
# DIALOG XEM MAT KHAU
# ============================================================

class ViewPasswordDialog(tk.Toplevel):
    def __init__(self, parent, entry):
        super().__init__(parent)

        self.title("Thông tin đăng nhập")
        self.geometry("560x360")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.transient(parent)
        self.grab_set()

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=30, pady=28)

        tk.Label(
            container,
            text=entry.get("service", "Tài khoản"),
            bg=BG,
            fg=TEXT,
            font=(FONT, 20, "bold"),
        ).pack(anchor="w")

        tk.Label(
            container,
            text=entry.get("username", ""),
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 10),
        ).pack(anchor="w", pady=(4, 22))

        self.password_var = tk.StringVar(
            value=entry.get("password", "")
        )

        tk.Label(
            container,
            text="MẬT KHẨU",
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        row = tk.Frame(container, bg=BG)
        row.pack(fill="x")

        self.show = False

        self.password_entry = make_entry(
            row,
            self.password_var,
            show="•",
        )
        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=10,
        )

        make_button(
            row,
            "Hiện",
            self.toggle,
        ).pack(side="left", padx=(8, 0))

        tk.Label(
            container,
            text="GHI CHÚ",
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(20, 6))

        note = entry.get("note", "")
        tk.Label(
            container,
            text=note if note else "Không có ghi chú.",
            bg=BG,
            fg=TEXT,
            justify="left",
            anchor="w",
            wraplength=500,
            font=(FONT, 10),
        ).pack(fill="x")

        make_button(
            container,
            "Đóng",
            self.destroy,
            primary=True,
        ).pack(anchor="e", pady=(22, 0))

    def toggle(self):
        self.show = not self.show
        self.password_entry.config(
            show="" if self.show else "•"
        )


# ============================================================
# UNLOCK / CREATE
# ============================================================

class StartScreen(tk.Frame):
    def __init__(self, root, on_unlock, has_vault):
        super().__init__(root, bg=BG)

        self.root = root
        self.on_unlock = on_unlock
        self.has_vault = has_vault

        self.pack(fill="both", expand=True)

        # Khung trung tam
        center = tk.Frame(self, bg=BG)
        center.place(relx=0.5, rely=0.5, anchor="center")

        # Logo
        logo = tk.Frame(
            center,
            bg="#082f49",
            width=82,
            height=82,
        )
        logo.pack()
        logo.pack_propagate(False)

        tk.Label(
            logo,
            text="K",
            bg="#082f49",
            fg=ACCENT,
            font=(FONT, 34, "bold"),
        ).place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            center,
            text="Trình quản lý mật khẩu PQC",
            bg=BG,
            fg=TEXT,
            font=(FONT, 26, "bold"),
        ).pack(pady=(18, 4))

        tk.Label(
            center,
            text="Quản lý mật khẩu với ML-KEM-768",
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 11),
        ).pack()

        card = tk.Frame(
            center,
            bg=CARD,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        card.pack(pady=(28, 0), ipadx=28, ipady=25)

        if has_vault:
            self.build_unlock(card)
        else:
            self.build_create(card)

    def build_unlock(self, card):
        tk.Label(
            card,
            text="Mở kho mật khẩu",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 17, "bold"),
        ).pack(anchor="w", padx=26, pady=(22, 5))

        tk.Label(
            card,
            text="Nhập mật khẩu chính để giải mã kho dữ liệu.",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 9),
        ).pack(anchor="w", padx=26, pady=(0, 18))

        self.password_var = tk.StringVar()

        entry = make_entry(
            card,
            self.password_var,
            show="•",
        )
        entry.pack(fill="x", padx=26, ipady=10)

        make_button(
            card,
            "Mở kho",
            self.unlock,
            primary=True,
        ).pack(fill="x", padx=26, pady=(18, 22))

        entry.focus_set()
        entry.bind("<Return>", lambda e: self.unlock())

    def build_create(self, card):
        tk.Label(
            card,
            text="Tạo kho mật khẩu mới",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 17, "bold"),
        ).pack(anchor="w", padx=26, pady=(22, 5))

        tk.Label(
            card,
            text="Kho sẽ được mã hóa trước khi ghi vào đĩa.",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 9),
        ).pack(anchor="w", padx=26, pady=(0, 18))

        make_button(
            card,
            "Tạo kho mới",
            self.create,
            primary=True,
        ).pack(fill="x", padx=26, pady=(0, 22))

    def unlock(self):
        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "Thiếu mật khẩu",
                "Vui lòng nhập mật khẩu chính.",
                parent=self.root,
            )
            return

        self.on_unlock(password, False)

    def create(self):
        dialog = PasswordDialog(
            self.root,
            "Tạo mật khẩu chính",
            "Mật khẩu này dùng để mở kho trong tương lai.",
            confirm=True,
        )

        if dialog.result:
            self.on_unlock(dialog.result, True)


# ============================================================
# GIAO DIEN CHINH
# ============================================================

class PasswordManagerGUI(tk.Frame):
    def __init__(
        self,
        root,
        secure,
        vault,
        encrypted_vault,
        master_password,
    ):
        super().__init__(root, bg=BG)

        self.root = root
        self.secure = secure
        self.vault = vault

        # Danh sách này là nguồn dữ liệu duy nhất mà giao diện sử dụng.
        # Giữ cùng một tham chiếu xuyên suốt vòng đời cửa sổ để tránh
        # trường hợp thêm dữ liệu vào một danh sách nhưng Treeview đọc
        # từ một đối tượng khác.
        self.entries = self.vault.get_entries()

        self.encrypted_vault = encrypted_vault
        self.master_password = master_password

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_tree())

        self.status_var = tk.StringVar(value="Kho đang mở")
        self.count_var = tk.StringVar(value="0 tài khoản")

        self.pack(fill="both", expand=True)

        self.build_ui()
        self.refresh_tree()

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------

    def build_ui(self):
        # SIDEBAR
        sidebar = tk.Frame(self, bg=SIDEBAR, width=290)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo
        logo_area = tk.Frame(sidebar, bg=SIDEBAR)
        logo_area.pack(fill="x", padx=20, pady=25)

        logo = tk.Frame(
            logo_area,
            bg="#082f49",
            width=48,
            height=48,
        )
        logo.pack(side="left")
        logo.pack_propagate(False)

        tk.Label(
            logo,
            text="K",
            bg="#082f49",
            fg=ACCENT,
            font=(FONT, 22, "bold"),
        ).place(relx=0.5, rely=0.5, anchor="center")

        title_box = tk.Frame(logo_area, bg=SIDEBAR)
        title_box.pack(side="left", padx=11, fill="x", expand=True)

        tk.Label(
            title_box,
            text="Kho mật khẩu PQC",
            bg=SIDEBAR,
            fg=TEXT,
            font=(FONT, 13, "bold"),
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="ML-KEM-768",
            bg=SIDEBAR,
            fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")

        # Section
        tk.Label(
            sidebar,
            text="KHO MẬT KHẨU",
            bg=SIDEBAR,
            fg="#64748b",
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=22, pady=(12, 8))

        self.nav_button(
            sidebar,
            "▣   Tất cả tài khoản",
            self.focus_search_all,
            active=True,
        )

        tk.Label(
            sidebar,
            text="HỆ THỐNG",
            bg=SIDEBAR,
            fg="#64748b",
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=22, pady=(20, 8))

        self.nav_button(
            sidebar,
            "🔑   Đổi mật khẩu chủ",
            self.change_master_password,
        )

        self.nav_button(
            sidebar,
            "⇥   Thoát ứng dụng",
            self.exit_application,
        )

        # Security card
        security = tk.Frame(
            sidebar,
            bg=CARD,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        security.pack(side="bottom", fill="x", padx=14, pady=14)

        tk.Label(
            security,
            text="BẢO MẬT",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=14, pady=(13, 8))

        for label in [
            "✓ ML-KEM-768",
            "✓ HKDF-SHA256",
            "✓ AES-256-GCM",
            "✓ Scrypt",
        ]:
            tk.Label(
                security,
                text=label,
                bg=CARD,
                fg=GREEN,
                font=(FONT, 9),
            ).pack(anchor="w", padx=14, pady=2)

        tk.Label(
            security,
            text="Mã hóa dữ liệu trước khi lưu",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 8),
        ).pack(anchor="w", padx=14, pady=(8, 13))

        # MAIN
        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        self.build_topbar(main)
        self.build_content(main)

    def nav_button(self, parent, text, command, active=False):
        bg = "#172554" if active else SIDEBAR
        fg = ACCENT if active else TEXT_MUTED

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground="#1e3a5f",
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            anchor="w",
            padx=18,
            pady=12,
            cursor="hand2",
            font=(FONT, 10, "bold"),
        )
        button.pack(fill="x", padx=10, pady=2)

    def build_topbar(self, parent):
        top = tk.Frame(parent, bg=BG, height=92)
        top.pack(fill="x", padx=28, pady=(22, 0))
        top.pack_propagate(False)

        left = tk.Frame(top, bg=BG)
        left.pack(side="left", fill="y")

        tk.Label(
            left,
            text="Kho mật khẩu",
            bg=BG,
            fg=TEXT,
            font=(FONT, 24, "bold"),
        ).pack(anchor="w")

        tk.Label(
            left,
            textvariable=self.count_var,
            bg=BG,
            fg=TEXT_MUTED,
            font=(FONT, 9),
        ).pack(anchor="w", pady=(3, 0))

        actions = tk.Frame(top, bg=BG)
        actions.pack(side="right", fill="y")

        make_button(
            actions,
            "Lưu kho",
            self.save_vault,
            primary=True,
        ).pack(side="left", padx=(0, 8))

        make_button(
            actions,
            "Khóa kho",
            self.lock_vault,
        ).pack(side="left")

    def build_content(self, parent):
        content = tk.Frame(parent, bg=BG)
        content.pack(fill="both", expand=True, padx=28, pady=(0, 25))

        # Search card
        search_card = tk.Frame(
            content,
            bg=CARD,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        search_card.pack(fill="x", pady=(0, 14))

        tk.Label(
            search_card,
            text="⌕",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 19),
        ).pack(side="left", padx=(16, 4))

        search = tk.Entry(
            search_card,
            textvariable=self.search_var,
            bg=CARD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            font=(FONT, 10),
        )
        search.pack(side="left", fill="x", expand=True, ipady=12)

        make_button(
            search_card,
            "＋ Thêm",
            self.add_entry,
            primary=True,
        ).pack(side="right", padx=8, pady=7)

        # Table card
        table_card = tk.Frame(
            content,
            bg=CARD,
            highlightthickness=1,
            highlightbackground=BORDER,
        )
        table_card.pack(fill="both", expand=True)

        heading = tk.Frame(table_card, bg=CARD)
        heading.pack(fill="x", padx=18, pady=(15, 10))

        tk.Label(
            heading,
            text="Tài khoản của bạn",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 12, "bold"),
        ).pack(side="left")

        tk.Label(
            heading,
            text="Nhấp đúp để xem chi tiết",
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 8),
        ).pack(side="right")

        table_area = tk.Frame(table_card, bg=CARD)
        table_area.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        columns = ("service", "username", "password", "note")

        # Tạo khung bảng TRƯỚC, sau đó Treeview được tạo trực tiếp
        # bên trong khung này. Không dùng pack(in_=...) để tránh làm
        # Treeview biến mất trên một số phiên bản Tk/Tkinter.
        table_border = tk.Frame(
            table_area,
            bg=BORDER,
            bd=0,
            highlightthickness=0,
        )
        table_border.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8),
        )

        self.tree = ttk.Treeview(
            table_border,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading(
            "service",
            text="DỊCH VỤ / WEBSITE",
            anchor="center",
        )
        self.tree.heading(
            "username",
            text="TÊN ĐĂNG NHẬP",
            anchor="center",
        )
        self.tree.heading(
            "password",
            text="MẬT KHẨU",
            anchor="center",
        )
        self.tree.heading(
            "note",
            text="GHI CHÚ",
            anchor="center",
        )

        # Các cột tự giãn theo cửa sổ và nội dung được căn giữa.
        self.tree.column(
            "service",
            width=250,
            minwidth=180,
            anchor="center",
            stretch=True,
        )
        self.tree.column(
            "username",
            width=270,
            minwidth=200,
            anchor="center",
            stretch=True,
        )
        self.tree.column(
            "password",
            width=220,
            minwidth=160,
            anchor="center",
            stretch=True,
        )
        self.tree.column(
            "note",
            width=270,
            minwidth=180,
            anchor="center",
            stretch=True,
        )

        # Đặt Treeview trực tiếp vào table_border.
        self.tree.pack(
            side="left",
            fill="both",
            expand=True,
            padx=1,
            pady=1,
        )

        scrollbar = ttk.Scrollbar(
            table_area,
            orient="vertical",
            command=self.tree.yview,
        )
        scrollbar.pack(side="right", fill="y")

        self.tree.configure(yscrollcommand=scrollbar.set)

        # Màu xen kẽ giúp phân biệt từng hàng rõ hơn.
        self.tree.tag_configure(
            "even",
            background=CARD,
            foreground=TEXT,
        )
        self.tree.tag_configure(
            "odd",
            background="#223047",
            foreground=TEXT,
        )

        self.tree.bind("<Double-1>", self.view_selected)
        self.tree.bind("<Return>", self.view_selected)

        # Context/action bar
        bottom = tk.Frame(table_card, bg=CARD)
        bottom.pack(fill="x", padx=18, pady=(0, 15))

        make_button(
            bottom,
            "Xem",
            self.view_selected,
        ).pack(side="left", padx=(0, 7))

        make_button(
            bottom,
            "Sửa",
            self.edit_selected,
        ).pack(side="left", padx=7)

        make_button(
            bottom,
            "Xóa",
            self.delete_selected,
        ).pack(side="left", padx=7)

        self.status_label = tk.Label(
            bottom,
            textvariable=self.status_var,
            bg=CARD,
            fg=TEXT_MUTED,
            font=(FONT, 8),
        )
        self.status_label.pack(side="right")

    # --------------------------------------------------------
    # DU LIEU
    # --------------------------------------------------------

    def get_entries(self):
        return self.entries

    def refresh_tree(self, select_index=None):
        if not hasattr(self, "tree"):
            return

        # Xóa toàn bộ dòng cũ.
        for item in self.tree.get_children():
            self.tree.delete(item)

        keyword = self.search_var.get().strip().lower()
        entries = self.entries
        visible = []

        for index, entry in enumerate(entries):
            service = str(entry.get("service", ""))
            username = str(entry.get("username", ""))
            password = str(entry.get("password", ""))
            note = str(entry.get("note", ""))

            searchable = f"{service} {username} {note}".lower()

            if keyword and keyword not in searchable:
                continue

            item_id = f"entry_{index}"
            visible.append(index)

            self.tree.insert(
                "",
                "end",
                iid=item_id,
                values=(
                    service,
                    username,
                    mask_password(password),
                    note,
                ),
                tags=("even" if len(visible) % 2 else "odd",),
            )

        if keyword:
            self.count_var.set(
                f"{len(entries)} tài khoản • {len(visible)} kết quả"
            )
        else:
            self.count_var.set(f"{len(entries)} tài khoản")

        # Nếu vừa thêm/sửa một mục, chọn đúng dòng đó.
        if select_index is not None:
            item_id = f"entry_{select_index}"
            if self.tree.exists(item_id):
                self.tree.selection_set(item_id)
                self.tree.focus(item_id)
                self.tree.see(item_id)

    def selected_index(self):
        selected = self.tree.selection()

        if not selected:
            messagebox.showinfo(
                "Chưa chọn tài khoản",
                "Hãy chọn một tài khoản trước.",
                parent=self.root,
            )
            return None

        item_id = selected[0]

        if item_id.startswith("entry_"):
            return int(item_id.split("_", 1)[1])

        return int(item_id)

    # --------------------------------------------------------
    # ACTION
    # --------------------------------------------------------

    def focus_search_all(self):
        self.search_var.set("")

    def add_entry(self):
        dialog = EntryDialog(self.root)

        if not dialog.result:
            return

        new_entry = {
            "service": dialog.result["service"],
            "username": dialog.result["username"],
            "password": dialog.result["password"],
            "note": dialog.result["note"],
        }

        # Ghi vào đúng danh sách mà Treeview đọc.
        self.entries.append(new_entry)

        new_index = len(self.entries) - 1

        # Xóa bộ lọc tìm kiếm.
        self.search_var.set("")

        # Làm mới danh sách và chọn ngay tài khoản vừa thêm.
        self.refresh_tree(select_index=new_index)

        # Cập nhật giao diện ngay lập tức.
        self.tree.update_idletasks()
        self.update_idletasks()

        self.status(
            "Đã thêm tài khoản. Hãy lưu kho để mã hóa thay đổi."
        )

    def edit_selected(self):
        index = self.selected_index()

        if index is None:
            return

        entry = self.entries[index]

        dialog = EntryDialog(self.root, entry)

        if not dialog.result:
            return

        entry.update(dialog.result)

        self.refresh_tree(select_index=index)
        self.status("Đã cập nhật tài khoản. Hãy lưu kho.")

    def delete_selected(self):
        index = self.selected_index()

        if index is None:
            return

        entry = self.entries[index]

        answer = messagebox.askyesno(
            "Xóa tài khoản",
            (
                f"Bạn có chắc muốn xóa tài khoản:\n\n"
                f"{entry.get('service', '')}\n"
                f"{entry.get('username', '')}\n\n"
                "Thao tác này sẽ có hiệu lực sau khi lưu kho."
            ),
            parent=self.root,
        )

        if not answer:
            return

        del self.entries[index]

        self.refresh_tree()
        self.status("Đã xóa tài khoản. Hãy lưu kho để ghi thay đổi.")

    def view_selected(self, event=None):
        index = self.selected_index()

        if index is None:
            return

        entry = self.entries[index]
        ViewPasswordDialog(self.root, entry)

    def change_master_password(self):
        """Đổi mật khẩu chủ bằng cách bảo vệ lại khóa bí mật ML-KEM."""

        first = PasswordDialog(
            self.root,
            "Đổi mật khẩu chủ",
            "Nhập mật khẩu chủ hiện tại.",
            confirm=False,
        )

        old_password = first.result
        if not old_password:
            return

        # Không sử dụng mật khẩu hiện tại trong giao diện nếu nhập sai.
        if old_password != self.master_password:
            messagebox.showerror(
                "Mật khẩu không đúng",
                "Mật khẩu chủ hiện tại không chính xác.",
                parent=self.root,
            )
            return

        second = PasswordDialog(
            self.root,
            "Mật khẩu chủ mới",
            "Nhập mật khẩu chủ mới để bảo vệ kho.",
            confirm=True,
        )

        new_password = second.result
        if not new_password:
            return

        if new_password == self.master_password:
            messagebox.showwarning(
                "Mật khẩu không thay đổi",
                "Mật khẩu mới phải khác mật khẩu chủ hiện tại.",
                parent=self.root,
            )
            return

        try:
            self.status("Đang thay đổi mật khẩu chủ...")
            self.root.update_idletasks()

            # Khôi phục khóa bí mật ML-KEM bằng mật khẩu cũ.
            secret_key = restore_secret_key_gui(
                self.encrypted_vault["protected_secret_key"],
                self.master_password,
            )

            # Bảo vệ lại chính khóa bí mật đó bằng mật khẩu mới.
            new_protected_secret_key = protect_secret_key_gui(
                secret_key,
                new_password,
            )

            if not isinstance(new_protected_secret_key, dict):
                raise RuntimeError(
                    "Dữ liệu bảo vệ khóa bí mật không hợp lệ."
                )

            # Tạo bản sao dữ liệu kho trong RAM, chỉ cập nhật phần
            # protected_secret_key. Dữ liệu mật khẩu đã mã hóa không
            # cần mã hóa lại chỉ vì đổi mật khẩu chủ.
            updated_vault = dict(self.encrypted_vault)
            updated_vault["protected_secret_key"] = new_protected_secret_key

            # Ghi tệp trước.
            save_vault(updated_vault)

            # Đọc lại và kiểm tra có thể mở kho bằng mật khẩu mới.
            saved_data = load_vault()
            verify_vault = PasswordVault()

            safe_call_decrypt(
                self.secure,
                saved_data,
                new_password,
                verify_vault,
            )

            # Kiểm tra số lượng bản ghi không thay đổi.
            if len(verify_vault.get_entries()) != len(self.entries):
                raise RuntimeError(
                    "Kiểm tra sau khi đổi mật khẩu thất bại: "
                    "số lượng tài khoản đã thay đổi."
                )

            # Chỉ cập nhật trạng thái của phiên làm việc sau khi
            # tệp đã được ghi và xác minh thành công.
            self.encrypted_vault = saved_data
            self.master_password = new_password

            self.status("Đã đổi mật khẩu chủ thành công.")

            messagebox.showinfo(
                "Đổi mật khẩu thành công",
                (
                    "Mật khẩu chủ đã được thay đổi thành công.\n\n"
                    "Khóa bí mật ML-KEM đã được bảo vệ lại bằng "
                    "mật khẩu mới."
                ),
                parent=self.root,
            )

        except Exception as exc:
            self.status("Đổi mật khẩu chủ thất bại.")

            messagebox.showerror(
                "Không thể đổi mật khẩu",
                (
                    "Không thể đổi mật khẩu chủ.\n\n"
                    f"Chi tiết: {exc}\n\n"
                    "Kho hiện tại chưa được đổi mật khẩu."
                ),
                parent=self.root,
            )

    def on_close(self):
        """Đóng ứng dụng thông qua cửa sổ gốc App."""
        self.root.on_close()

    def exit_application(self):
        answer = messagebox.askyesno(
            "Thoát ứng dụng",
            (
                "Bạn có chắc muốn thoát ứng dụng?\n\n"
                "Hãy chắc chắn rằng mọi thay đổi đã được lưu."
            ),
            parent=self.root,
        )

        if not answer:
            return

        # on_close() thuộc lớp App, không thuộc PasswordManagerGUI.
        self.root.on_close()

    def save_vault(self):
        try:
            self.status("Đang mã hóa và lưu kho...")
            self.root.update_idletasks()

            # Luu lai so luong muc truoc khi ma hoa de kiem tra
            # sau khi ghi file.
            expected_entries = list(self.vault.get_entries())
            expected_count = len(expected_entries)

            encrypted = safe_call_encrypt_existing(
                self.secure,
                self.encrypted_vault,
                self.vault,
                self.master_password,
            )

            if not isinstance(encrypted, dict):
                raise RuntimeError(
                    "Hàm mã hóa kho không trả về dữ liệu kho hợp lệ."
                )

            # Ghi file ma hoa.
            save_vault(encrypted)

            # Doc lai file vua ghi va giai ma lai vao mot vault tam.
            # Buoc nay tranh tinh trang giao dien bao 'Da luu' nhung
            # file tren dia khong chua du lieu vua them.
            saved_data = load_vault()

            if not isinstance(saved_data, dict):
                raise RuntimeError(
                    "Tệp vault.json sau khi lưu không hợp lệ."
                )

            verify_vault = PasswordVault()

            safe_call_decrypt(
                self.secure,
                saved_data,
                self.master_password,
                verify_vault,
            )

            actual_entries = verify_vault.get_entries()

            if len(actual_entries) != expected_count:
                raise RuntimeError(
                    "Kiểm tra sau khi lưu thất bại: "
                    f"mong đợi {expected_count} tài khoản, "
                    f"nhưng tệp chỉ chứa {len(actual_entries)}."
                )

            # Kiem tra noi dung tung muc, khong chi kiem tra so luong.
            if actual_entries != expected_entries:
                raise RuntimeError(
                    "Kiểm tra sau khi lưu thất bại: "
                    "dữ liệu trong tệp không trùng với kho đang mở."
                )

            # Chi cap nhat trang thai trong RAM sau khi xac minh file.
            self.encrypted_vault = saved_data

            self.refresh_tree()
            self.status("Đã lưu và kiểm tra kho thành công.")

            messagebox.showinfo(
                "Đã lưu",
                (
                    "Kho mật khẩu đã được mã hóa và lưu thành công.\n\n"
                    f"Đã xác minh {expected_count} tài khoản trong tệp."
                ),
                parent=self.root,
            )

        except Exception as exc:
            self.status("Lưu kho thất bại.")
            messagebox.showerror(
                "Lỗi lưu kho",
                f"Không thể lưu kho:\n\n{exc}",
                parent=self.root,
            )

    def lock_vault(self):
        answer = messagebox.askyesno(
            "Khóa kho",
            (
                "Bạn có muốn khóa kho mật khẩu?\n\n"
                "Các thay đổi chưa lưu sẽ bị mất."
            ),
            parent=self.root,
        )

        if not answer:
            return

        self.destroy()

        # Giam tham chieu den du lieu nhay cam trong giao dien.
        self.vault = None
        self.encrypted_vault = None
        self.master_password = None

        self.root.show_start_screen()

    def status(self, text):
        self.status_var.set(text)


# ============================================================
# UNG DUNG CHINH
# ============================================================

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(MIN_WIDTH, MIN_HEIGHT)
        self.configure(bg=BG)

        setup_style(self)

        # Co the thay doi icon sau khi dong goi exe.
        try:
            self.iconname("Trình quản lý mật khẩu PQC")
        except tk.TclError:
            pass

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.secure = SecureVault()

        self.show_start_screen()

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_start_screen(self):
        self.clear_screen()

        encrypted = load_vault()

        self.start_screen = StartScreen(
            self,
            self.open_vault,
            has_vault=encrypted is not None,
        )

    def open_vault(self, master_password, create_new=False):
        try:
            self.config(cursor="wait")
            self.update_idletasks()

            if create_new:
                vault = PasswordVault()

                encrypted_vault = safe_call_create(
                    self.secure,
                    vault,
                    master_password,
                )

                save_vault(encrypted_vault)

            else:
                encrypted_vault = load_vault()

                if encrypted_vault is None:
                    raise RuntimeError(
                        "Không tìm thấy tệp kho mật khẩu."
                    )

                vault = PasswordVault()

                safe_call_decrypt(
                    self.secure,
                    encrypted_vault,
                    master_password,
                    vault,
                )

            self.clear_screen()

            self.main_gui = PasswordManagerGUI(
                self,
                self.secure,
                vault,
                encrypted_vault,
                master_password,
            )

        except Exception:
            # Khong hien chi tiet loi giai ma ra man hinh.
            # Neu mat khau sai, nguoi dung chi can thu lai.
            messagebox.showerror(
                "Không thể mở kho",
                (
                    "Không thể mở kho mật khẩu.\n\n"
                    "Kiểm tra mật khẩu chính hoặc tính toàn vẹn "
                    "của tệp vault.json."
                ),
                parent=self,
            )

        finally:
            self.config(cursor="")

    def on_close(self):
        try:
            self.secure.close()
        except Exception:
            pass

        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
