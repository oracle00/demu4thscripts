# -*- coding: utf-8 -*-
# gui_track_processor.py

import tkinter as tk
from tkinter import ttk, filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD
from pathlib import Path


# ------------------------------
# 基本処理関数
# ------------------------------

def reverse_bits(byte_val: int) -> int:
    rev = 0
    for i in range(8):
        rev = (rev << 1) | ((byte_val >> i) & 1)
    return rev


def calc_bcc(data: bytes) -> int:
    bcc = 0
    for b in data:
        bcc ^= b
    return bcc


def format_track(track_data: bytes) -> bytes:
    """69バイトのデータをトラック形式にする"""
    bcc = calc_bcc(track_data)
    bcc_not = (~bcc) & 0xFF
    return bytes([0xFF]) + track_data + bytes([0xFF, bcc_not])


def detect_track_format(data: bytes) -> bool:
    """トラックデータ形式かどうか判定（簡易判定）"""
    if len(data) < 4:
        return False
    if data[0] != 0xFF:
        return False
    return True


def split_into_tracks(data: bytes):
    """69バイトごとにトラック化"""
    tracks = []
    for i in range(0, len(data), 69):
        chunk = data[i:i+69]
        if not chunk:
            continue
        tracks.append(format_track(chunk))
    return tracks


def restore_from_tracks(tracks: list[bytes]) -> bytes:
    """トラックデータからカードバイナリを復元"""
    restored = b""
    for t in tracks:
        if len(t) < 4:
            continue
        body = t[1:-2]  # 先頭1バイトと末尾2バイトを削除
        restored += body
    return restored


# ------------------------------
# 入力処理
# ------------------------------

def process_file(path: Path):
    # 入力データ読み込み
    try:
        text = path.read_text().strip()
        data = bytes.fromhex(text)
        input_type = "HEXテキスト"
    except Exception:
        data = path.read_bytes()
        input_type = "バイナリ"

    # トラックデータ判定
    is_track = detect_track_format(data)

    if is_track:
        input_type = "トラックデータ"

        # トラックを抽出
        tracks = []
        idx = 0
        track_len = 1 + 69 + 2
        while idx + track_len <= len(data):
            if data[idx] != 0xFF:
                break
            t = data[idx:idx + track_len]
            tracks.append(t)
            idx += track_len

        # 入力データフレーム → トラック形式表示
        input_display = "\n".join(" ".join(f"{b:02X}" for b in t) for t in tracks)

        # 出力データ → トラック復元 → ビット順逆転 → HEX表示
        restored = restore_from_tracks(tracks)
        reversed_bytes = bytes(reverse_bits(b) for b in restored)
        output_hex = " ".join(f"{b:02X}" for b in reversed_bytes)

    else:
        # バイナリ or HEX → 入力データフレームは生データのHEX表示
        input_display = " ".join(f"{b:02X}" for b in data)

        # 出力データ → まずビット順逆転、その後トラック化
        reversed_bytes = bytes(reverse_bits(b) for b in data)
        tracks = split_into_tracks(reversed_bytes)
        output_hex = "\n".join("".join(f"{b:02X}" for b in t) for t in tracks)

    return input_type, input_display, output_hex


# ------------------------------
# GUI 操作
# ------------------------------

def save_text(text_widget, default_name):
    content = text_widget.get("1.0", tk.END).strip()
    if not content:
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=default_name,
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        Path(file_path).write_text(content)


def on_drop(event):
    file_path = Path(event.data.strip("{}"))
    file_label.config(text=str(file_path))

    input_type, input_display, output_display = process_file(file_path)

    type_label.config(text=f"入力は {input_type} として認識しました")

    text_input.delete("1.0", tk.END)
    text_input.insert(tk.END, input_display)

    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, output_display)


# ------------------------------
# GUI 構築
# ------------------------------

root = TkinterDnD.Tk()
root.title("Track Data Processor")
root.geometry("640x480")

# ダークテーマ
style = ttk.Style()
style.theme_use("clam")

dark_bg = "#1e1e1e"
dark_fg = "#ffffff"
accent = "#3c3c3c"

style.configure(".", background=dark_bg, foreground=dark_fg)
style.configure("TLabel", background=dark_bg, foreground=dark_fg)
style.configure("TButton", background=accent, foreground=dark_fg)
style.map("TButton", background=[("active", "#505050")])

root.configure(bg=dark_bg)

# ファイルパス表示
file_label = ttk.Label(root, text="ファイル未選択")
file_label.pack(pady=3)

# 入力タイプ表示
type_label = ttk.Label(root, text="")
type_label.pack(pady=3)

# ドロップ領域（枠線付き）
drop_label = tk.Label(
    root,
    text="ここにファイルをドラッグ＆ドロップ",
    bg="#2e2e2e",
    fg=dark_fg,
    bd=2,
    relief="solid",
    highlightthickness=2,
    highlightbackground="#555555",
    padx=10,
    pady=10
)
drop_label.pack(pady=8, fill="x", padx=10)

drop_label.drop_target_register(DND_FILES)
drop_label.dnd_bind("<<Drop>>", on_drop)

frame = ttk.Frame(root)
frame.pack(fill="both", expand=True, padx=5, pady=5)

# 入力データフレーム
ttk.Label(frame, text="入力データ").grid(row=0, column=0, sticky="w")
ttk.Button(frame, text="入力データを保存",
           command=lambda: save_text(text_input, "input_data.txt")).grid(row=1, column=0, sticky="w")
text_input = tk.Text(frame, height=8, wrap="word",
                     bg=accent, fg=dark_fg, insertbackground=dark_fg)
text_input.grid(row=2, column=0, sticky="nsew")

# 出力データフレーム
ttk.Label(frame, text="出力データ").grid(row=3, column=0, sticky="w", pady=(4, 0))
ttk.Button(frame, text="出力データを保存",
           command=lambda: save_text(text_output, "output_data.txt")).grid(row=4, column=0, sticky="w")
text_output = tk.Text(frame, height=8, wrap="word",
                      bg=accent, fg=dark_fg, insertbackground=dark_fg)
text_output.grid(row=5, column=0, sticky="nsew")

# レイアウト調整
frame.rowconfigure(2, weight=1)
frame.rowconfigure(5, weight=1)
frame.columnconfigure(0, weight=1)

root.mainloop()