import subprocess
import time
import threading
import ctypes
from ctypes import wintypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ------------------------------
# WinAPI Definitions
# ------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
WriteProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# ------------------------------
# Configuration
# ------------------------------
DEFAULT_DEMUL_CMD = r'D:\VO4\demul_251211\demul.exe -run=hikaru -rom=von4'
DEFAULT_BASE_ADDR = 0x011BF880

CARD_SIZE = 207
PATTERN = bytes([0x53, 0x45, 0x47, 0x41, 0x42, 0x44, 0x58, 0x30])
PATTERN_LEN = len(PATTERN)
PATTERN_OFFSET_FROM_BASE = 138
FILE_PATTERN_OFFSET = 138

UPDATE_INTERVAL_MS = 1000

# Toggle Switch Configuration
TOGGLE_ADDR = 0x2C5B796C
TOGGLE_VALUE = 0x1E

# Dark Theme Colors
DARK_BG = "#1E1E1E"
DARK_FG = "#E0E0E0"
DARK_FRAME_BG = "#252525"
DARK_BUTTON_BG = "#2D2D2D"
DARK_BUTTON_FG = "#E0E0E0"

FLASH_BG = "#E0E0E0"
FLASH_FG = "#1E1E1E"


def read_process_memory(h_process, address, size):
    buf = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t(0)
    ok = ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
    if not ok or bytes_read.value == 0:
        return None
    return bytes(buf[: bytes_read.value])


def write_process_memory(h_process, address, data: bytes):
    size = len(data)
    buf = (ctypes.c_ubyte * size).from_buffer_copy(data)
    bytes_written = ctypes.c_size_t(0)
    ok = WriteProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_written))
    if not ok or bytes_written.value != size:
        raise OSError("WriteProcessMemory failed")


def scan_for_pattern(h_process):
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while True:
        result = VirtualQueryEx(h_process, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if result == 0:
            break

        if mbi.State == MEM_COMMIT and mbi.Protect in (0x04, 0x40, 0x02, 0x20):
            region_base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value
            region_size = mbi.RegionSize
            data = read_process_memory(h_process, region_base, region_size)
            if data:
                idx = data.find(PATTERN)
                if idx != -1:
                    return region_base + idx - PATTERN_OFFSET_FROM_BASE

        addr += mbi.RegionSize

    return None


def bytes_to_hex_str(data: bytes):
    return " ".join(f"{b:02X}" for b in data)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Demul Card Data Monitor")
        self.geometry("900x420")
        self.resizable(False, False)

        self.proc = None
        self.h_process = None
        self.base_addr = DEFAULT_BASE_ADDR
        self.last_card_data = None
        self.monitoring = False
        self.overwrite_data = None

        self.blink_count = 0
        self.blink_on = False

        self.toggle_enabled = False

        self.setup_style()
        self.create_widgets()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=DARK_BG, foreground=DARK_FG)
        style.configure("TFrame", background=DARK_BG)
        style.configure("TLabel", background=DARK_BG, foreground=DARK_FG)
        style.configure("TLabelframe", background=DARK_BG, foreground=DARK_FG)
        style.configure("TLabelframe.Label", background=DARK_BG, foreground=DARK_FG)
        style.configure("TButton", background=DARK_BUTTON_BG, foreground=DARK_BUTTON_FG)
        style.configure("RedFrame.TLabelframe", background=DARK_BG, foreground=DARK_FG,
                        bordercolor="red", borderwidth=2, relief="solid")
        style.configure("RedFrame.TLabelframe.Label", background=DARK_BG, foreground="red")
        self.configure(bg=DARK_BG)

    def create_widgets(self):

        # -------------------------
        # Demul Launch Command Configuration
        # -------------------------
        cmd_frame = ttk.Frame(self)
        cmd_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(cmd_frame, text="Demul Launch Command:").pack(side="left")
        self.demul_cmd_var = tk.StringVar(value=DEFAULT_DEMUL_CMD)

        entry = ttk.Entry(cmd_frame, textvariable=self.demul_cmd_var, width=80)
        entry.configure(foreground="black")
        entry.pack(side="left", padx=5)

        ttk.Button(cmd_frame, text="Save", command=self.save_demul_cmd).pack(side="left", padx=5)

        # -------------------------
        # Top Control Panel
        # -------------------------
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=5, pady=5)

        ttk.Button(top_frame, text="Start Demul & Connect", command=self.start_demul).pack(side="left", padx=5)
        ttk.Button(top_frame, text="Stop Demul", command=self.stop_demul).pack(side="left", padx=5)

        ttk.Label(top_frame, text="Base Address:").pack(side="left")
        self.base_addr_var = tk.StringVar(value=f"0x{DEFAULT_BASE_ADDR:08X}")
        ttk.Label(top_frame, textvariable=self.base_addr_var).pack(side="left", padx=5)

        self.use_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top_frame, text="Get via Pattern Scan", variable=self.use_scan_var).pack(side="left", padx=10)

        self.btn_scan = ttk.Button(top_frame, text="Run Pattern Scan", command=self.run_scan)
        self.btn_scan.pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="Status: Not Connected")
        ttk.Label(top_frame, textvariable=self.status_var).pack(side="left", padx=10)

        # -------------------------
        # Middle Layout
        # -------------------------
        middle_frame = ttk.Frame(self)
        middle_frame.pack(fill="both", expand=True, padx=2, pady=2)

        # Left: Current Card Data
        current_frame = ttk.LabelFrame(middle_frame, text="Current Card Data (Memory)")
        current_frame.pack(side="left", fill="both", expand=True, padx=2, pady=2)

        self.min_current = tk.Frame(current_frame, width=360, height=180, bg=DARK_FRAME_BG)
        self.min_current.pack_propagate(False)
        self.min_current.pack(fill="none", padx=2, pady=2)

        self.txt_current = tk.Text(
            self.min_current, wrap="word",
            bg=DARK_FRAME_BG, fg=DARK_FG, insertbackground=DARK_FG,
            borderwidth=1, relief="solid"
        )
        self.txt_current.pack(fill="both", expand=True)

        bottom_current = ttk.Frame(current_frame)
        bottom_current.pack(fill="x", padx=2, pady=2)

        self.last_update_var = tk.StringVar(value="Update: Not retrieved yet")
        ttk.Label(bottom_current, textvariable=self.last_update_var).pack(side="left", padx=3)

        self.btn_save_current = ttk.Button(bottom_current, text="Save Current Card Data",
                                           command=self.save_current_data, state="disabled")
        self.btn_save_current.pack(side="right", padx=3)

        # -------------------------
        # Right: Overwrite Card Data (Red Frame)
        # -------------------------
        overwrite_frame = ttk.LabelFrame(
            middle_frame, text="Overwrite Card Data", style="RedFrame.TLabelframe"
        )
        overwrite_frame.pack(side="left", fill="both", expand=True, padx=2, pady=2)

        self.min_overwrite = tk.Frame(overwrite_frame, width=360, height=180, bg=DARK_FRAME_BG)
        self.min_overwrite.pack_propagate(False)
        self.min_overwrite.pack(fill="none", padx=2, pady=2)

        self.txt_overwrite = tk.Text(
            self.min_overwrite, wrap="word",
            bg=DARK_FRAME_BG, fg=DARK_FG, insertbackground=DARK_FG,
            borderwidth=1, relief="solid", width=1, height=1
        )
        self.txt_overwrite.pack(fill="both", expand=True)
        self.txt_overwrite.bind("<KeyRelease>", self.validate_overwrite_text)

        bottom_overwrite = ttk.Frame(overwrite_frame)
        bottom_overwrite.pack(fill="x", padx=2, pady=2)

        self.overwrite_status_var = tk.StringVar(value="Select file")
        ttk.Label(bottom_overwrite, textvariable=self.overwrite_status_var).pack(side="left", padx=5)

        self.btn_overwrite = ttk.Button(bottom_overwrite, text="Overwrite Memory",
                                        command=self.do_overwrite, state="disabled")
        self.btn_overwrite.pack(side="right", padx=5)

        # -------------------------
        # Input File Path Display (Button on Right)
        # -------------------------
        path_frame = ttk.Frame(self)
        path_frame.pack(fill="x", padx=5, pady=(0, 5))

        ttk.Label(path_frame, text="Input File:").pack(side="left")

        self.input_path_var = tk.StringVar(value="")
        entry_path = ttk.Entry(path_frame, textvariable=self.input_path_var, width=100)
        entry_path.configure(foreground="black")
        entry_path.pack(side="left", padx=5, fill="x", expand=True)

        self.btn_open_file = ttk.Button(path_frame, text="Open Overwrite File",
                                        command=self.open_overwrite_file)
        self.btn_open_file.pack(side="right", padx=5)

        # -------------------------
        # Toggle Switch Panel
        # -------------------------
        toggle_frame = ttk.LabelFrame(self, text="Card Value Fix")
        toggle_frame.pack(fill="x", padx=5, pady=5)

        self.toggle_var = tk.BooleanVar(value=False)
        self.toggle_check = ttk.Checkbutton(
            toggle_frame, text="Enable Restore Card Uses",
            variable=self.toggle_var,
            command=self.toggle_fixed_value
        )
        self.toggle_check.pack(side="left", padx=10)

        self.toggle_status_var = tk.StringVar(value="Disabled")
        ttk.Label(toggle_frame, textvariable=self.toggle_status_var).pack(side="left", padx=10)

    # --------------------------
    # Save Demul Launch Command
    # --------------------------
    def save_demul_cmd(self):
        messagebox.showinfo("Save Complete", "Demul launch command updated.")

    # --------------------------
    # Start Demul
    # --------------------------
    def start_demul(self):
        cmd = self.demul_cmd_var.get()

        if self.proc is not None and self.proc.poll() is None:
            messagebox.showinfo("Information", "Already connected to Demul.")
            return

        try:
            self.proc = subprocess.Popen(cmd)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Demul:\n{e}")
            return

        pid = self.proc.pid
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        h_process = OpenProcess(access, False, pid)

        if not h_process:
            messagebox.showerror("Error", "OpenProcess failed")
            self.proc = None
            return

        self.h_process = h_process
        self.status_var.set(f"Status: Demul Started (PID={pid})")
        self.monitoring = True
        self.after(UPDATE_INTERVAL_MS, self.update_card_data_loop)

    # --------------------------
    # Stop Demul
    # --------------------------
    def stop_demul(self):
        self.monitoring = False
        self.toggle_enabled = False
        self.toggle_var.set(False)
        self.toggle_status_var.set("Disabled")

        if self.h_process:
            CloseHandle(self.h_process)
            self.h_process = None

        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

        self.proc = None
        self.status_var.set("Status: Demul Stopped")
        self.last_update_var.set("Update: Monitoring Stopped")
        self.base_addr = DEFAULT_BASE_ADDR
        self.base_addr_var.set(f"0x{DEFAULT_BASE_ADDR:08X}")

    # --------------------------
    # Pattern Scan
    # --------------------------
    def run_scan(self):
        if not self.h_process:
            messagebox.showwarning("Warning", "Connect to Demul before scanning.")
            return

        self.status_var.set("Status: Pattern Scanning...")
        self.btn_scan.config(state="disabled")

        def worker():
            base = scan_for_pattern(self.h_process)

            def done():
                if base:
                    self.base_addr = base
                    self.base_addr_var.set(f"0x{base:08X}")
                    self.status_var.set(f"Status: Scan Complete (0x{base:08X})")
                else:
                    self.status_var.set("Status: Pattern not found")

                self.btn_scan.config(state="normal")

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    # --------------------------
    # Toggle Value Fix
    # --------------------------
    def toggle_fixed_value(self):
        self.toggle_enabled = self.toggle_var.get()
        if self.toggle_enabled:
            self.toggle_status_var.set("Enabled")
        else:
            self.toggle_status_var.set("Disabled")

    # --------------------------
    # Memory Monitoring
    # --------------------------
    def update_card_data_loop(self):
        if not self.monitoring or not self.h_process:
            return

        if self.proc is None or self.proc.poll() is not None:
            self.status_var.set("Status: Demul Process Ended")
            self.monitoring = False
            self.toggle_enabled = False
            self.toggle_var.set(False)
            self.toggle_status_var.set("Disabled")
            return

        data = read_process_memory(self.h_process, self.base_addr, CARD_SIZE)

        if data and len(data) == CARD_SIZE:
            if data != self.last_card_data:
                self.last_card_data = data
                self.txt_current.delete("1.0", "end")
                self.txt_current.insert("1.0", bytes_to_hex_str(data))
                self.last_update_var.set(f"Update: Change detected at {time.strftime('%H:%M:%S')}")
                self.btn_save_current.config(state="normal")
                self.start_frame_blink()
        else:
            self.last_update_var.set("Update: Read failed")

        # Write memory fixed value
        if self.toggle_enabled:
            try:
                write_process_memory(self.h_process, TOGGLE_ADDR, bytes([TOGGLE_VALUE]))
            except Exception:
                pass

        self.after(UPDATE_INTERVAL_MS, self.update_card_data_loop)

    # --------------------------
    # Frame Blinking
    # --------------------------
    def start_frame_blink(self):
        self.blink_count = 0
        self.blink_on = False
        self._blink_step()

    def _blink_step(self):
        if self.blink_count >= 6:
            self.restore_frame_colors()
            return

        self.blink_on = not self.blink_on

        if self.blink_on:
            self.min_current.configure(bg=FLASH_BG)
            self.txt_current.configure(bg=FLASH_BG, fg=FLASH_FG, insertbackground=FLASH_FG)
        else:
            self.min_current.configure(bg=DARK_FRAME_BG)
            self.txt_current.configure(bg=DARK_FRAME_BG, fg=DARK_FG, insertbackground=DARK_FG)

        self.blink_count += 1
        self.after(200, self._blink_step)

    def restore_frame_colors(self):
        self.min_current.configure(bg=DARK_FRAME_BG)
        self.txt_current.configure(bg=DARK_FRAME_BG, fg=DARK_FG, insertbackground=DARK_FG)

    # --------------------------
    # Save Current Data
    # --------------------------
    def save_current_data(self):
        if not self.last_card_data:
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if not path:
            return

        with open(path, "wb") as f:
            f.write(self.last_card_data)

        messagebox.showinfo("Save Complete", f"Saved:\n{path}")


    # --------------------------
    # Validate Overwrite Text (Paste Support)
    # --------------------------
    def validate_overwrite_text(self, event=None):
        text_content = self.txt_overwrite.get("1.0", "end").strip()
        
        if not text_content:
            self.overwrite_data = None
            self.overwrite_status_var.set("Select file")
            self.btn_overwrite.config(state="disabled")
            return

        try:
            # Convert hex text to byte array
            hex_values = text_content.split()
            data = bytes(int(h, 16) for h in hex_values)
        except (ValueError, TypeError):
            self.overwrite_data = None
            self.overwrite_status_var.set("Invalid: Not valid hexadecimal format")
            self.btn_overwrite.config(state="disabled")
            return

        if len(data) != CARD_SIZE:
            self.overwrite_data = None
            self.overwrite_status_var.set(f"Invalid: Size is not {CARD_SIZE} bytes")
            self.btn_overwrite.config(state="disabled")
            return

        if data[FILE_PATTERN_OFFSET:FILE_PATTERN_OFFSET + PATTERN_LEN] != PATTERN:
            self.overwrite_data = None
            self.overwrite_status_var.set("Invalid: Pattern not found at byte 138")
            self.btn_overwrite.config(state="disabled")
            return

        self.overwrite_data = data
        self.overwrite_status_var.set("Valid card data")
        self.btn_overwrite.config(state="normal")

    # --------------------------
    # Open Overwrite File
    # --------------------------
    def open_overwrite_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            self.overwrite_status_var.set("Could not open file")
            self.input_path_var.set(path)
            self.btn_overwrite.config(state="disabled")
            return

        self.input_path_var.set(path)

        if len(data) != CARD_SIZE:
            self.overwrite_status_var.set(f"Invalid: Size is not {CARD_SIZE} bytes")
            self.btn_overwrite.config(state="disabled")
            return

        if data[FILE_PATTERN_OFFSET:FILE_PATTERN_OFFSET + PATTERN_LEN] != PATTERN:
            self.overwrite_status_var.set("Invalid: Pattern not found at byte 138")
            self.btn_overwrite.config(state="disabled")
            return

        self.overwrite_data = data
        self.txt_overwrite.delete("1.0", "end")
        self.txt_overwrite.insert("1.0", bytes_to_hex_str(data))

        self.overwrite_status_var.set("Valid card data")
        self.btn_overwrite.config(state="normal")

    # --------------------------
    # Overwrite Memory
    # --------------------------
    def do_overwrite(self):
        if not self.h_process or self.proc is None or self.proc.poll() is not None:
            messagebox.showwarning("Warning", "Not connected to Demul.")
            return

        if not self.overwrite_data or len(self.overwrite_data) != CARD_SIZE:
            messagebox.showwarning("Warning", "No valid overwrite data.")
            return

        if not messagebox.askyesno("Confirm", "Overwrite card data in memory. Continue?"):
            return

        try:
            write_process_memory(self.h_process, self.base_addr, self.overwrite_data)
            messagebox.showinfo("Complete", "Memory overwrite completed.")
        except Exception as e:
            messagebox.showerror("Error", f"Memory overwrite failed:\n{e}")

    # --------------------------
    # Window Close Handler
    # --------------------------
    def on_close(self):
        self.stop_demul()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
