"""
gui.py — Simple GUI for Secure File Lifecycle Manager
=======================================================
Intentionally minimal. Black background, white panels,
slightly off-grid layout — honest student project energy.

Run with:
    python -X utf8 gui.py
"""

import sys
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

# make sure crypto_engine is importable from the same folder
sys.path.insert(0, os.path.dirname(__file__))

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    verify_integrity,
    hash_file,
    IntegrityError,
    HASH_EXTENSION,
)
from shred_engine import secure_shred_file


# ──────────────────────────────────────────────
# COLOUR PALETTE  (two colours, that's it)
# ──────────────────────────────────────────────
BG      = "#0a0a0a"   # almost-black background
PANEL   = "#ffffff"   # white panels / boxes
TEXT_D  = "#0a0a0a"   # dark text on white panels
TEXT_L  = "#ffffff"   # light text on black
ACCENT  = "#c0c0c0"   # grey — buttons, borders
RED     = "#ff4444"   # error / alert
GREEN   = "#44ff88"   # success
MONO    = ("Courier New", 10)
TITLE   = ("Courier New", 13, "bold")
SMALL   = ("Courier New", 9)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Lifecycle Manager")
        self.configure(bg=BG)
        self.resizable(False, False)

        # ── state vars ────────────────────────
        self.file_path = tk.StringVar(value="")
        self.password  = tk.StringVar(value="")
        self.status_msg = tk.StringVar(value="ready.")
        self.log_lines  = []          # list of strings for the log box

        self._build_ui()
        self.geometry("680x540")      # fixed window, slightly off-square on purpose

    # ──────────────────────────────────────────
    # BUILD
    # ──────────────────────────────────────────
    def _build_ui(self):
        # ── raw title, left-aligned (not centered) ───────────────────────────
        tk.Label(
            self, text="[ secure file lifecycle manager ]",
            bg=BG, fg=TEXT_L, font=("Courier New", 11, "bold"),
            anchor="w", padx=14,
        ).pack(fill="x", pady=(12, 0))

        tk.Label(
            self, text="  week 3-4 build  //  layer 1, 2 + 4 active (shred)",
            bg=BG, fg=ACCENT, font=SMALL, anchor="w", padx=14,
        ).pack(fill="x")

        # ── separator ────────────────────────────────────────────────────────
        tk.Frame(self, bg=ACCENT, height=1).pack(fill="x", padx=12, pady=6)

        # ── top half: two white panels side by side ───────────────────────────
        row1 = tk.Frame(self, bg=BG)
        row1.pack(fill="x", padx=12, pady=4)

        self._file_panel(row1)
        self._password_panel(row1)

        # ── action buttons row (slightly left-heavy, not centered) ────────────
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill="x", padx=12, pady=(8, 0))
        self._build_buttons(btn_frame)

        # ── status bar ────────────────────────────────────────────────────────
        status_box = tk.Frame(self, bg=PANEL, bd=0, highlightthickness=1,
                              highlightbackground=ACCENT)
        status_box.pack(fill="x", padx=12, pady=8)

        tk.Label(status_box, text="status :", bg=PANEL, fg=TEXT_D,
                 font=("Courier New", 9, "bold"), padx=6).pack(side="left")
        self._status_lbl = tk.Label(
            status_box, textvariable=self.status_msg,
            bg=PANEL, fg=TEXT_D, font=MONO, anchor="w",
        )
        self._status_lbl.pack(side="left", fill="x", expand=True)

        # ── log panel (white rectangle, monospace, slightly too tall) ─────────
        log_outer = tk.Frame(self, bg=BG)
        log_outer.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        tk.Label(
            log_outer, text="event log", bg=BG, fg=ACCENT,
            font=SMALL, anchor="w",
        ).pack(anchor="w")

        log_inner = tk.Frame(log_outer, bg=PANEL, bd=0,
                             highlightthickness=1, highlightbackground=ACCENT)
        log_inner.pack(fill="both", expand=True)

        self._log_text = tk.Text(
            log_inner, bg=PANEL, fg=TEXT_D, font=MONO,
            relief="flat", bd=0, padx=8, pady=6,
            state="disabled", wrap="word",
            cursor="arrow",
        )
        self._log_text.pack(fill="both", expand=True)

    # ──────────────────────────────────────────
    # PANELS
    # ──────────────────────────────────────────
    def _file_panel(self, parent):
        """White rectangle holding the file path entry."""
        box = tk.Frame(parent, bg=PANEL, bd=0,
                       highlightthickness=1, highlightbackground=ACCENT,
                       width=340, height=80)
        box.pack(side="left", padx=(0, 8))
        box.pack_propagate(False)

        tk.Label(box, text="file", bg=PANEL, fg=TEXT_D,
                 font=("Courier New", 9), anchor="w", padx=8
                 ).pack(anchor="w", pady=(8, 0))

        row = tk.Frame(box, bg=PANEL)
        row.pack(fill="x", padx=8, pady=4)

        entry = tk.Entry(row, textvariable=self.file_path,
                         bg="#f0f0f0", fg=TEXT_D, relief="flat",
                         font=MONO, bd=1, width=30)
        entry.pack(side="left", fill="x", expand=True)

        tk.Button(
            row, text="...", font=SMALL, bg=BG, fg=TEXT_L,
            relief="flat", bd=0, padx=6, cursor="hand2",
            command=self._browse,
        ).pack(side="left", padx=(4, 0))

    def _password_panel(self, parent):
        """White rectangle holding the password field."""
        box = tk.Frame(parent, bg=PANEL, bd=0,
                       highlightthickness=1, highlightbackground=ACCENT,
                       width=290, height=80)
        box.pack(side="left")
        box.pack_propagate(False)

        tk.Label(box, text="password", bg=PANEL, fg=TEXT_D,
                 font=("Courier New", 9), anchor="w", padx=8
                 ).pack(anchor="w", pady=(8, 0))

        entry = tk.Entry(box, textvariable=self.password,
                         show="*", bg="#f0f0f0", fg=TEXT_D,
                         relief="flat", font=MONO, bd=1, width=28)
        entry.pack(padx=8, pady=4, anchor="w")

    def _build_buttons(self, parent):
        """Five action buttons — flat, black on black outline, uneven gaps."""
        buttons = [
            ("encrypt",  self._do_encrypt),
            ("decrypt",  self._do_decrypt),
            ("verify",   self._do_verify),
            ("shred",    self._do_shred),
            ("hash",     self._do_hash),
        ]
        # purposely uneven padding to keep student aesthetic
        pads = [0, 5, 5, 8, 12]
        for (label, cmd), lpad in zip(buttons, pads):
            tk.Button(
                parent, text=label, command=cmd,
                bg=PANEL, fg=TEXT_D, font=("Courier New", 10, "bold"),
                relief="flat", bd=0, padx=14, pady=8,
                cursor="hand2", activebackground=ACCENT,
                highlightthickness=1, highlightbackground=ACCENT,
            ).pack(side="left", padx=(lpad, 0))

    # ──────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────
    def _browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            self._log(f"selected: {os.path.basename(path)}")

    def _log(self, msg: str, color: str = TEXT_D):
        """Append a line to the event log text box."""
        self.log_lines.append(msg)
        self._log_text.config(state="normal")
        self._log_text.insert("end", f"  {msg}\n")
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    def _set_status(self, msg: str, ok: bool = True):
        self.status_msg.set(msg)
        self._status_lbl.config(fg=GREEN if ok else RED)

    def _get_inputs(self):
        """Return (file_path, password) or (None, None) with an error log."""
        fp = self.file_path.get().strip()
        pw = self.password.get()
        if not fp:
            self._log("! no file selected")
            self._set_status("no file selected.", ok=False)
            return None, None
        if not pw:
            self._log("! no password entered")
            self._set_status("enter a password.", ok=False)
            return None, None
        return fp, pw

    # ──────────────────────────────────────────
    # ACTIONS  (run in threads so UI doesn't freeze)
    # ──────────────────────────────────────────
    def _run_threaded(self, fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()

    def _do_encrypt(self):
        fp, pw = self._get_inputs()
        if not fp:
            return
        self._log(f"encrypting {os.path.basename(fp)} ...")
        self._set_status("encrypting ...", ok=True)

        def task():
            try:
                out = encrypt_file(fp, pw)
                self.after(0, lambda: self._log(f"done -> {os.path.basename(out)}"))
                self.after(0, lambda: self._set_status("encrypted ok.", ok=True))
            except Exception as e:
                self.after(0, lambda: self._log(f"! {e}"))
                self.after(0, lambda: self._set_status("encryption failed.", ok=False))

        self._run_threaded(task)

    def _do_decrypt(self):
        fp, pw = self._get_inputs()
        if not fp:
            return
        self._log(f"verifying + decrypting {os.path.basename(fp)} ...")
        self._set_status("decrypting ...", ok=True)

        def task():
            try:
                out = decrypt_file(fp, pw)
                self.after(0, lambda: self._log(f"done -> {os.path.basename(out)}"))
                self.after(0, lambda: self._set_status("decrypted ok.", ok=True))
            except IntegrityError as e:
                self.after(0, lambda: self._log(f"! INTEGRITY VIOLATION: {e}"))
                self.after(0, lambda: self._set_status("integrity check FAILED.", ok=False))
            except Exception as e:
                self.after(0, lambda: self._log(f"! {e}"))
                self.after(0, lambda: self._set_status("decryption failed.", ok=False))

        self._run_threaded(task)

    def _do_verify(self):
        fp = self.file_path.get().strip()
        if not fp:
            self._log("! no file selected")
            self._set_status("select an .enc file first.", ok=False)
            return

        hash_path = fp + HASH_EXTENSION
        if not os.path.isfile(hash_path):
            self._log(f"! no .hash file found for {os.path.basename(fp)}")
            self._set_status("missing .hash file.", ok=False)
            return

        self._log(f"verifying {os.path.basename(fp)} ...")

        def task():
            try:
                verify_integrity(fp, hash_path)
                self.after(0, lambda: self._log("integrity check PASSED — file is clean"))
                self.after(0, lambda: self._set_status("integrity OK.", ok=True))
            except IntegrityError:
                self.after(0, lambda: self._log("! TAMPER DETECTED — hash mismatch"))
                self.after(0, lambda: self._set_status("TAMPERED FILE!", ok=False))

        self._run_threaded(task)

    def _do_shred(self):
        fp = self.file_path.get().strip()
        if not fp:
            self._log("! no file selected")
            self._set_status("select a file to shred.", ok=False)
            return

        if not os.path.isfile(fp):
            self._log(f"! file not found: {os.path.basename(fp)}")
            self._set_status("file not found.", ok=False)
            return

        # Prompt user confirmation
        confirm = messagebox.askyesno(
            "Confirm Permanent Shred",
            f"Are you SURE you want to permanently destroy:\n\n{os.path.basename(fp)}\n\n"
            "This will overwrite sectors in 3 passes and cannot be undone!"
        )
        if not confirm:
            self._log("shred operation cancelled by user")
            self._set_status("shred aborted.", ok=True)
            return

        self._log(f"shredding {os.path.basename(fp)} (3-pass DoD standard)...")
        self._set_status("shredding sectors...", ok=True)

        def task():
            try:
                cert = secure_shred_file(fp, passes=3)
                self.after(0, lambda: self._log(f"erased: {cert['original_file']}"))
                self.after(0, lambda: self._log(f"cert-id: {cert['certificate_id']}"))
                self.after(0, lambda: self._log(f"pre-hash: {cert['pre_shred_sha256'][:16]}..."))
                self.after(0, lambda: self._set_status("file shredded & sanitized.", ok=True))
                # Clear path
                self.after(0, lambda: self.file_path.set(""))
            except Exception as e:
                self.after(0, lambda: self._log(f"! shred error: {e}"))
                self.after(0, lambda: self._set_status("shred failed.", ok=False))

        self._run_threaded(task)

    def _do_hash(self):
        fp = self.file_path.get().strip()
        if not fp:
            self._log("! no file selected")
            self._set_status("select a file first.", ok=False)
            return

        self._log(f"hashing {os.path.basename(fp)} ...")

        def task():
            try:
                digest = hash_file(fp)
                short  = digest[:16] + "..."
                self.after(0, lambda: self._log(f"SHA-256: {digest}"))
                self.after(0, lambda: self._set_status(f"sha256: {short}", ok=True))
            except Exception as e:
                self.after(0, lambda: self._log(f"! {e}"))
                self.after(0, lambda: self._set_status("hash failed.", ok=False))

        self._run_threaded(task)


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
