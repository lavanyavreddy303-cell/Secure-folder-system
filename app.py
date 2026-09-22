import tkinter as tk
from tkinter import ttk, filedialog
import ctypes
import platform
import os
import subprocess
from pathlib import Path

from core.keys import Session, init_user
from core.errors import AuthError, WrongPassphraseError, SecureFolderError
from core.pipeline import list_entries, export_public_key, share_file
from ui.theme import ACCENT, MUTED, get_fonts, BG, DANGER, TEXT, SURFACE, SUCCESS, BORDER
from ui.widgets import StepIndicator, PipelineTrace, Card, PrimaryButton, SecondaryButton, DangerButton, DarkDialog, Badge
from ui.controller import TaskController, EventMsg, ProgressMsg, ResultMsg, ErrorMsg

class App(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.parent = parent
        self.pack(fill="both", expand=True)
        self.session = Session()
        self.storage_dir = Path("./secure_storage")
        
        self.fonts = get_fonts()
        self.controller = TaskController()
        
        # State variables
        self.current_stage = 1
        self.op_type = None  # "encrypt" or "decrypt"
        self.target_path = None  # Path object for encrypt
        self.target_ids = []  # list of file_ids for decrypt
        self.dest_dir = None # Path object for decrypt dest
        self.delete_originals = tk.BooleanVar(value=False)
        self.op_results = None # ResultMsg payload
        self.op_error = None # Error string if failed
        
        self._setup_window()
        self._build_layout()
        self._show_stage(1)
        self._poll_autolock()
        self._poll_queue()

    def _setup_window(self):
        self.parent.title("Cryptix | Secure Folder System")
        self.parent.geometry("1100x700")
        self.parent.minsize(960, 620)
        
        if platform.system() == "Windows":
            try:
                DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                hwnd = ctypes.windll.user32.GetParent(self.parent.winfo_id())
                value = ctypes.c_int(2)
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value))
            except Exception:
                pass

    def _build_layout(self):
        top_bar = tk.Frame(self, bg=BG, padx=24, pady=16)
        top_bar.pack(fill="x")
        
        logo_lbl = tk.Label(top_bar, text="CRYPTIX", font=self.fonts["title"], fg=ACCENT, bg=BG)
        logo_lbl.pack(side="left")
        
        sub_lbl = tk.Label(top_bar, text="Secure Folder System", font=self.fonts["body"], fg=MUTED, bg=BG)
        sub_lbl.pack(side="left", padx=(8, 0), pady=(6, 0))
        
        self.logout_btn = SecondaryButton(top_bar, text="Logout", command=self.logout)
        
        self.status_lbl = tk.Label(top_bar, text="● Locked", font=self.fonts["small"], fg=MUTED, bg=BG)
        self.status_lbl.pack(side="right", pady=(8, 0))
        
        content = tk.Frame(self, bg=BG)
        content.pack(fill="both", expand=True, padx=24, pady=(0, 24))
        
        left_panel = tk.Frame(content, bg=BG, width=150)
        left_panel.pack(side="left", fill="y", padx=(0, 24))
        left_panel.pack_propagate(False)
        self.step_ind = StepIndicator(left_panel)
        self.step_ind.pack(fill="x", pady=24)
        
        self.main_panel = tk.Frame(content, bg=BG)
        self.main_panel.pack(side="left", fill="both", expand=True)
        
        right_panel = tk.Frame(content, bg=BG, width=300)
        right_panel.pack(side="right", fill="y", padx=(24, 0))
        right_panel.pack_propagate(False)
        tk.Label(right_panel, text="PIPELINE", font=self.fonts["small"], fg=MUTED, bg=BG).pack(anchor="w", pady=(0, 8))
        self.trace = PipelineTrace(right_panel)
        self.trace.pack(fill="both", expand=True)
        
        bottom_bar = tk.Frame(self, bg=BG, padx=24, pady=8)
        bottom_bar.pack(fill="x", side="bottom")
        self.bottom_status = tk.Label(bottom_bar, text="", fg=MUTED, bg=BG, font=self.fonts["small"])
        self.bottom_status.pack(side="left")
        self.progress = ttk.Progressbar(bottom_bar, style="TProgressbar", mode="determinate", maximum=1.0)

    def _show_stage(self, stage):
        self.current_stage = stage
        for widget in self.main_panel.winfo_children():
            widget.destroy()
            
        if stage == 1:
            self.step_ind.set_step(0)
            self.logout_btn.pack_forget()
            self.status_lbl.configure(text="● Locked", fg=MUTED)
            self.progress.pack_forget()
            self.bottom_status.configure(text="")
            self.trace.reset("encrypt")
            self._build_stage1()
            
        elif stage == 2:
            self.step_ind.set_step(1)
            self.logout_btn.pack(side="right", padx=(16, 0))
            self.status_lbl.configure(text="● Unlocked", fg=ACCENT)
            self.progress.pack_forget()
            self.bottom_status.configure(text="")
            self.op_type = None
            self.target_path = None
            self.target_ids = []
            self.op_results = None
            self.op_error = None
            self._build_stage2()
            
        elif stage == 3:
            self.step_ind.set_step(2)
            self.trace.reset(self.op_type)
            self.progress.pack(side="right", fill="x", expand=True, padx=(16, 0))
            self.progress["value"] = 0.0
            self._build_stage3()
            
        elif stage == 4:
            self.step_ind.set_step(3)
            self.progress.pack_forget()
            self.bottom_status.configure(text="")
            self._build_stage4()

    # -------------------------------------------------------------------------
    # STAGE 1: Login
    # -------------------------------------------------------------------------

    def _build_stage1(self):
        card = Card(self.main_panel)
        card.pack(pady=40, padx=40, anchor="center")
        
        inner = tk.Frame(card, bg=card["bg"], padx=32, pady=32)
        inner.pack()
        
        keys_exist = (self.storage_dir / "keys" / "public.pem").exists()
        title_text = "Unlock" if keys_exist else "Create your keys"
        tk.Label(inner, text=title_text, font=self.fonts["heading"], bg=card["bg"], fg=TEXT).pack(anchor="w", pady=(0, 16))
        
        self.err_lbl = tk.Label(inner, text="", font=self.fonts["small"], fg=DANGER, bg=card["bg"])
        self.err_lbl.pack(anchor="w", pady=(0, 8))
        
        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(inner, textvariable=self.pw_var, show="●", width=40)
        pw_entry.pack(anchor="w", pady=(0, 8))
        
        if not keys_exist:
            tk.Label(inner, text="Confirm passphrase", font=self.fonts["small"], bg=card["bg"], fg=MUTED).pack(anchor="w", pady=(8, 4))
            self.pw_conf_var = tk.StringVar()
            pw_conf_entry = ttk.Entry(inner, textvariable=self.pw_conf_var, show="●", width=40)
            pw_conf_entry.pack(anchor="w", pady=(0, 8))
            
            hint = tk.Label(inner, text="Min 10 characters.", font=self.fonts["small"], fg=MUTED, bg=card["bg"])
            hint.pack(anchor="w", pady=(0, 16))
            
            PrimaryButton(inner, text="Create", command=self._handle_create).pack(anchor="w")
        else:
            show_var = tk.IntVar()
            def toggle_show():
                pw_entry.configure(show="" if show_var.get() else "●")
            ttk.Checkbutton(inner, text="Show passphrase", variable=show_var, command=toggle_show).pack(anchor="w", pady=(0, 16))
            PrimaryButton(inner, text="Unlock", command=self._handle_unlock).pack(anchor="w")
            pw_entry.bind("<Return>", lambda e: self._handle_unlock())
            
        pw_entry.focus_set()

    def _handle_create(self):
        pw = self.pw_var.get()
        conf = self.pw_conf_var.get()
        if pw != conf:
            self.err_lbl.configure(text="Passphrases do not match.")
            return
        try:
            init_user(self.storage_dir, pw)
            self._show_stage(1)
        except AuthError as e:
            self.err_lbl.configure(text=str(e))
        except Exception as e:
            self.err_lbl.configure(text=f"Unexpected error: {e}")

    def _handle_unlock(self):
        pw = self.pw_var.get()
        try:
            self.session.unlock(self.storage_dir, pw)
            self.err_lbl.configure(text="")
            self._show_stage(2)
        except WrongPassphraseError as e:
            self.err_lbl.configure(text=str(e))
        except AuthError as e:
            self.err_lbl.configure(text=str(e))
        except Exception as e:
            self.err_lbl.configure(text=f"Unexpected error: {e}")
            
    def logout(self):
        self.session.lock()
        self._show_stage(1)

    def _poll_autolock(self):
        if self.session.is_unlocked and self.session.is_expired():
            self.logout()
            DarkDialog(self.parent, "Session Expired", "Your session has automatically locked due to inactivity.", "info")
        self.after(5000, self._poll_autolock)

    # -------------------------------------------------------------------------
    # STAGE 2: Select
    # -------------------------------------------------------------------------

    def _build_stage2(self):
        grid = tk.Frame(self.main_panel, bg=BG)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=1, uniform="col")
        grid.columnconfigure(1, weight=1, uniform="col")
        grid.rowconfigure(0, weight=1)
        
        # Left: Encrypt
        enc_card = Card(grid)
        enc_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._build_encrypt_card(enc_card)
        
        # Right: Decrypt
        dec_card = Card(grid)
        dec_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self._build_decrypt_card(dec_card)

    def _build_encrypt_card(self, parent):
        inner = tk.Frame(parent, bg=SURFACE, padx=24, pady=24)
        inner.pack(fill="both", expand=True)
        
        tk.Label(inner, text="Encrypt a folder or file", font=self.fonts["heading"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
        
        btn_frame = tk.Frame(inner, bg=SURFACE)
        btn_frame.pack(anchor="w", pady=(0, 16))
        PrimaryButton(btn_frame, text="Select Folder", command=self._select_enc_folder).pack(side="left", padx=(0, 8))
        PrimaryButton(btn_frame, text="Select File", command=self._select_enc_file).pack(side="left")
        
        self.enc_preview_lbl = tk.Label(inner, text="", font=self.fonts["small"], bg=SURFACE, fg=MUTED, justify="left")
        self.enc_preview_lbl.pack(anchor="w")

        self.enc_path_lbl = tk.Label(inner, text="", font=self.fonts["mono"], bg=SURFACE, fg=TEXT, wraplength=350, justify="left")
        self.enc_path_lbl.pack(anchor="w", pady=(8, 16))
        
        self.enc_next_btn = PrimaryButton(inner, text="Next", command=self._go_to_stage3_enc)
        self.enc_next_btn.state(["disabled"])
        self.enc_next_btn.pack(anchor="w", side="bottom")

    def _build_decrypt_card(self, parent):
        inner = tk.Frame(parent, bg=SURFACE, padx=24, pady=24)
        inner.pack(fill="both", expand=True)
        
        tk.Label(inner, text="Decrypt from Secure Storage", font=self.fonts["heading"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
        
        # Treeview
        tree_frame = tk.Frame(inner, bg=SURFACE)
        tree_frame.pack(fill="both", expand=True, pady=(0, 16))
        
        cols = ("name", "size", "hash")
        self.dec_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.dec_tree.heading("name", text="Name", anchor="w")
        self.dec_tree.heading("size", text="Size", anchor="e")
        self.dec_tree.heading("hash", text="Hash Prefix", anchor="w")
        self.dec_tree.column("name", width=180, anchor="w")
        self.dec_tree.column("size", width=80, anchor="e")
        self.dec_tree.column("hash", width=100, anchor="w")
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.dec_tree.yview, style="Vertical.TScrollbar")
        self.dec_tree.configure(yscrollcommand=scrollbar.set)
        
        self.dec_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Populate
        try:
            entries = list_entries(self.session, self.storage_dir)
            for e in entries:
                size_str = self._human_size(e.size)
                self.dec_tree.insert("", "end", iid=e.file_id, values=(e.name, size_str, e.sha256_prefix))
        except Exception as e:
            DarkDialog(self.parent, "Error", f"Could not load storage: {e}", "error")
            
        def on_tree_select(event):
            selected = self.dec_tree.selection()
            if selected:
                self.dec_next_btn.state(["!disabled"])
            else:
                self.dec_next_btn.state(["disabled"])
                
        self.dec_tree.bind("<<TreeviewSelect>>", on_tree_select)
        
        btn_frame = tk.Frame(inner, bg=SURFACE)
        btn_frame.pack(fill="x", side="bottom")
        
        SecondaryButton(btn_frame, text="Select All", command=lambda: self.dec_tree.selection_set(self.dec_tree.get_children())).pack(side="left")
        
        self.dec_next_btn = PrimaryButton(btn_frame, text="Next", command=self._go_to_stage3_dec)
        self.dec_next_btn.state(["disabled"])
        self.dec_next_btn.pack(side="right")

    def _select_enc_folder(self):
        d = filedialog.askdirectory(title="Select Folder to Encrypt")
        if d:
            self._validate_and_set_enc(Path(d))

    def _select_enc_file(self):
        f = filedialog.askopenfilename(title="Select File to Encrypt")
        if f:
            self._validate_and_set_enc(Path(f))
            
    def _validate_and_set_enc(self, path: Path):
        try:
            # Cannot encrypt the storage dir itself or anything inside it
            if self.storage_dir.resolve() in path.resolve().parents or path.resolve() == self.storage_dir.resolve():
                raise ValueError("Cannot encrypt the secure storage directory itself.")
            if not path.exists():
                raise ValueError("Path does not exist.")
                
            self.target_path = path
            self.op_type = "encrypt"
            
            if path.is_dir():
                count, size, symlinks = 0, 0, 0
                for root, _, files in os.walk(path):
                    for name in files:
                        p = Path(root) / name
                        if p.is_symlink():
                            symlinks += 1
                        else:
                            count += 1
                            size += p.stat().st_size
                info = f"{count} files, {self._human_size(size)}"
                if symlinks > 0:
                    info += f"\n(Skipping {symlinks} symlinks)"
                self.enc_preview_lbl.configure(text=info)
            else:
                self.enc_preview_lbl.configure(text=f"1 file, {self._human_size(path.stat().st_size)}")
                
            self.enc_path_lbl.configure(text=str(path))
            self.enc_next_btn.state(["!disabled"])
        except Exception as e:
            self.target_path = None
            self.enc_next_btn.state(["disabled"])
            self.enc_preview_lbl.configure(text="")
            self.enc_path_lbl.configure(text="")
            DarkDialog(self.parent, "Invalid Selection", str(e), "error")

    def _go_to_stage3_enc(self):
        self._show_stage(3)

    def _go_to_stage3_dec(self):
        self.target_ids = list(self.dec_tree.selection())
        self.op_type = "decrypt"
        self._show_stage(3)

    # -------------------------------------------------------------------------
    # STAGE 3: Action
    # -------------------------------------------------------------------------

    def _build_stage3(self):
        card = Card(self.main_panel)
        card.pack(pady=40, padx=40, anchor="center")
        
        inner = tk.Frame(card, bg=card["bg"], padx=32, pady=32)
        inner.pack(fill="both", expand=True)
        
        if self.op_type == "encrypt":
            tk.Label(inner, text="Ready to Encrypt", font=self.fonts["heading"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
            tk.Label(inner, text=f"Target: {self.target_path.name}", font=self.fonts["body"], bg=SURFACE, fg=TEXT).pack(anchor="w")
            tk.Label(inner, text=str(self.target_path), font=self.fonts["mono"], bg=SURFACE, fg=MUTED, wraplength=400, justify="left").pack(anchor="w", pady=(4, 16))
            
            cb = ttk.Checkbutton(inner, text="Delete originals after verified encryption", variable=self.delete_originals, command=self._on_delete_orig_toggle)
            cb.pack(anchor="w", pady=(0, 24))
            
        else:
            tk.Label(inner, text="Ready to Decrypt", font=self.fonts["heading"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
            tk.Label(inner, text=f"{len(self.target_ids)} file(s) selected.", font=self.fonts["body"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
            
            # Dest dir picker
            dest_frame = tk.Frame(inner, bg=SURFACE)
            dest_frame.pack(fill="x", pady=(0, 24))
            tk.Label(dest_frame, text="Destination:", font=self.fonts["small"], bg=SURFACE, fg=MUTED).pack(side="left", padx=(0, 8))
            self.dest_lbl = tk.Label(dest_frame, text="(Not selected)", font=self.fonts["mono"], bg=SURFACE, fg=TEXT)
            self.dest_lbl.pack(side="left")
            SecondaryButton(dest_frame, text="Change", command=self._select_dest_dir).pack(side="right")
        
        btn_frame = tk.Frame(inner, bg=SURFACE)
        btn_frame.pack(anchor="w")
        
        self.btn_cancel = SecondaryButton(btn_frame, text="Cancel", command=self._cancel_task)
        self.btn_cancel.pack(side="left", padx=(0, 8))
        
        self.btn_start = PrimaryButton(btn_frame, text="Start", command=self._start_task)
        self.btn_start.pack(side="left")
        
        if self.op_type == "decrypt":
            self.btn_start.state(["disabled"]) # wait for dest dir

    def _on_delete_orig_toggle(self):
        if self.delete_originals.get():
            d = DarkDialog(self.parent, "Warning", "Original files will be deleted if encryption and verification succeed. On SSDs, secure deletion is not guaranteed, and forensic recovery may still be possible. Continue?", "confirm")
            self.wait_window(d)
            if not d.result:
                self.delete_originals.set(False)

    def _select_dest_dir(self):
        d = filedialog.askdirectory(title="Select Destination Folder")
        if d:
            self.dest_dir = Path(d)
            self.dest_lbl.configure(text=str(self.dest_dir))
            self.btn_start.state(["!disabled"])

    def _start_task(self):
        self.btn_start.state(["disabled"])
        self.btn_cancel.configure(text="Cancel Operation")
        self.bottom_status.configure(text="Starting...")
        
        if self.op_type == "encrypt":
            self.controller.start_encrypt(self.session, self.target_path, self.storage_dir, self.delete_originals.get())
        else:
            self.controller.start_decrypt(self.session, self.target_ids, self.storage_dir, self.dest_dir)

    def _cancel_task(self):
        if self.controller.is_running():
            self.controller.cancel()
            self.btn_cancel.state(["disabled"])
            self.bottom_status.configure(text="Cancelling...")
        else:
            self._show_stage(2)

    def _poll_queue(self):
        for msg in self.controller.poll():
            if isinstance(msg, EventMsg):
                self.trace.set_state(msg.step, "running", detail=msg.detail)
                self.bottom_status.configure(text=msg.detail)
                
                # Mark previous running step as done (simplified heuristic)
                for step_data in self.trace.step_frames:
                    if step_data["state"] == "running" and not step_data["name"].startswith(msg.step) and msg.step not in step_data["name"]:
                        self.trace.set_state(step_data["name"], "done")
                        
            elif isinstance(msg, ProgressMsg):
                self.progress["value"] = msg.fraction
            elif isinstance(msg, ResultMsg):
                # Mark all as done
                for step_data in self.trace.step_frames:
                    if step_data["state"] in ("running", "pending"):
                        self.trace.set_state(step_data["name"], "done")
                self.op_results = msg.data
                self._show_stage(4)
            elif isinstance(msg, ErrorMsg):
                for step_data in self.trace.step_frames:
                    if step_data["state"] == "running":
                        self.trace.set_state(step_data["name"], "failed")
                self.btn_start.state(["!disabled"])
                self.btn_cancel.state(["!disabled"])
                self.btn_cancel.configure(text="Back")
                DarkDialog(self.parent, "Error", msg.error, "error")
                self.bottom_status.configure(text="Failed.")
                self.progress["value"] = 0
                
        self.after(50, self._poll_queue)

    # -------------------------------------------------------------------------
    # STAGE 4: Result
    # -------------------------------------------------------------------------

    def _build_stage4(self):
        card = Card(self.main_panel)
        card.pack(fill="both", expand=True, pady=40, padx=40)
        
        inner = tk.Frame(card, bg=SURFACE, padx=32, pady=32)
        inner.pack(fill="both", expand=True)
        
        tk.Label(inner, text="Operation Complete", font=self.fonts["heading"], bg=SURFACE, fg=TEXT).pack(anchor="w", pady=(0, 16))
        
        if self.op_type == "encrypt":
            self._build_enc_result(inner)
        else:
            self._build_dec_result(inner)
            
        btn_frame = tk.Frame(inner, bg=SURFACE)
        btn_frame.pack(fill="x", side="bottom", pady=(16, 0))
        
        SecondaryButton(btn_frame, text="Start Over", command=lambda: self._show_stage(2)).pack(side="left")
        
        if self.op_type == "decrypt" and self.dest_dir and self.dest_dir.exists():
            PrimaryButton(btn_frame, text="Open Destination", command=self._open_dest).pack(side="right")
        elif self.op_type == "encrypt":
            PrimaryButton(btn_frame, text="Export Public Key", command=self._export_pub).pack(side="right", padx=(8, 0))
            self.share_btn = PrimaryButton(btn_frame, text="Share", command=self._share_item)
            self.share_btn.pack(side="right")
            # Only enable share if a single file was encrypted
            if "file_id" not in self.op_results:
                self.share_btn.state(["disabled"])

    def _build_enc_result(self, parent):
        if "summary" in self.op_results:
            summary = self.op_results["summary"]
            tk.Label(parent, text=f"Successfully encrypted {summary.encrypted} file(s).", font=self.fonts["body"], bg=SURFACE, fg=SUCCESS).pack(anchor="w")
            if summary.skipped:
                tk.Label(parent, text=f"Skipped {len(summary.skipped)} item(s).", font=self.fonts["body"], bg=SURFACE, fg=MUTED).pack(anchor="w")
            if summary.errors:
                tk.Label(parent, text=f"Errors on {len(summary.errors)} item(s).", font=self.fonts["body"], bg=SURFACE, fg=DANGER).pack(anchor="w")
        else:
            tk.Label(parent, text=f"File successfully encrypted.", font=self.fonts["body"], bg=SURFACE, fg=SUCCESS).pack(anchor="w")
            tk.Label(parent, text=f"File ID: {self.op_results['file_id']}", font=self.fonts["mono"], bg=SURFACE, fg=MUTED).pack(anchor="w", pady=(8, 0))

    def _build_dec_result(self, parent):
        results = self.op_results
        
        tampered = [r for r in results if r.status == "TAMPERED"]
        if tampered:
            banner = tk.Frame(parent, bg=DANGER, padx=16, pady=16)
            banner.pack(fill="x", pady=(0, 16))
            tk.Label(banner, text="CRITICAL WARNING: Tampering Detected", font=self.fonts["heading"], fg=BG, bg=DANGER).pack(anchor="w")
            tk.Label(banner, text="One or more files were modified or corrupted and have NOT been released to your destination folder.", font=self.fonts["body"], fg=BG, bg=DANGER, wraplength=600, justify="left").pack(anchor="w", pady=(4, 0))
            
        tree_frame = tk.Frame(parent, bg=SURFACE)
        tree_frame.pack(fill="both", expand=True)
        
        cols = ("file_id", "status", "expected", "actual")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        tree.heading("file_id", text="File ID", anchor="w")
        tree.heading("status", text="Status", anchor="w")
        tree.heading("expected", text="Expected Hash", anchor="w")
        tree.heading("actual", text="Actual Hash", anchor="w")
        tree.column("file_id", width=100)
        tree.column("status", width=80)
        tree.column("expected", width=150)
        tree.column("actual", width=150)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview, style="Vertical.TScrollbar")
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        for r in results:
            tag = "safe" if r.status == "SAFE" else "danger"
            tree.insert("", "end", values=(r.file_id, r.status, r.expected_hash[:16]+"...", r.actual_hash[:16]+"..." if r.actual_hash else "None"), tags=(tag,))
            
        tree.tag_configure("safe", foreground=SUCCESS)
        tree.tag_configure("danger", foreground=DANGER)

    def _open_dest(self):
        if not self.dest_dir or not self.dest_dir.exists():
            return
        p = str(self.dest_dir)
        try:
            if platform.system() == "Windows":
                os.startfile(p)
            elif platform.system() == "Darwin":
                subprocess.run(["open", p], check=False)
            else:
                subprocess.run(["xdg-open", p], check=False)
        except Exception as e:
            DarkDialog(self.parent, "Error", f"Could not open folder: {e}", "error")

    def _export_pub(self):
        out = filedialog.asksaveasfilename(title="Export Public Key", defaultextension=".pem", initialfile="public.pem")
        if out:
            try:
                export_public_key(self.storage_dir, out)
                DarkDialog(self.parent, "Success", f"Public key exported to:\n{out}")
            except Exception as e:
                DarkDialog(self.parent, "Error", str(e), "error")

    def _share_item(self):
        if "file_id" not in self.op_results:
            return
        fid = self.op_results["file_id"]
        
        pem_path = filedialog.askopenfilename(title="Select Recipient's Public Key", filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
        if not pem_path: return
        
        out_dir = filedialog.askdirectory(title="Select Destination Folder for Bundle")
        if not out_dir: return
        
        try:
            pem_bytes = Path(pem_path).read_bytes()
            share_file(self.session, fid, self.storage_dir, pem_bytes, Path(out_dir) / f"shared_{fid}")
            DarkDialog(self.parent, "Success", f"Shared bundle created in {out_dir}")
        except Exception as e:
            DarkDialog(self.parent, "Error", str(e), "error")

    def _human_size(self, n: int) -> str:
        for unit in ("B", "KiB", "MiB", "GiB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TiB"
