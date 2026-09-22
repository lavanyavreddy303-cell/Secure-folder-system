import tkinter as tk
from tkinter import ttk
from ui.theme import BG, SURFACE, ELEVATED, BORDER, TEXT, MUTED, ACCENT, SUCCESS, DANGER, get_fonts

class Card(tk.Frame):
    def __init__(self, parent, **kwargs):
        # We use tk.Frame for the 1px border capability (highlightthickness)
        super().__init__(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1, **kwargs)

class PrimaryButton(ttk.Button):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style="Accent.TButton", **kwargs)

class SecondaryButton(ttk.Button):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style="TButton", **kwargs)

class DangerButton(ttk.Button):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style="Danger.TButton", **kwargs)

class StepIndicator(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self.steps = ["1 User", "2 Select", "3 Encrypt / Decrypt", "4 Result"]
        self.labels = []
        fonts = get_fonts()
        
        for step in self.steps:
            lbl = tk.Label(self, text=step, bg=BG, fg=MUTED, font=fonts["small"], anchor="w", padx=8, pady=4)
            lbl.pack(fill="x", pady=2)
            self.labels.append(lbl)
            
    def set_step(self, n):
        for i, lbl in enumerate(self.labels):
            if i < n:
                # Done
                lbl.configure(fg=SUCCESS, text="✓ " + self.steps[i][2:])
            elif i == n:
                # Active
                lbl.configure(fg=ACCENT, text=self.steps[i])
            else:
                # Upcoming
                lbl.configure(fg=MUTED, text=self.steps[i])

class Badge(tk.Label):
    def __init__(self, parent, status, **kwargs):
        fonts = get_fonts()
        color = SUCCESS if status == "SAFE" else DANGER
        super().__init__(parent, text=status, bg=color, fg=BG, font=fonts["small"], padx=6, pady=2, **kwargs)

class PipelineTrace(Card):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.fonts = get_fonts()
        self.step_frames = []
        
    def reset(self, kind="encrypt"):
        for widget in self.winfo_children():
            widget.destroy()
            
        self.step_frames = []
        if kind == "encrypt":
            steps = ["SHA-256 hash created", "AES-256 file encrypted", "AES key RSA-encrypted", "Stored securely", "Verified"]
        else:
            steps = ["AES key RSA-decrypted", "AES-256 file decrypted", "SHA-256 hash compared", "Result: SAFE / TAMPERED"]
            
        for step in steps:
            frame = tk.Frame(self, bg=SURFACE)
            frame.pack(fill="x", pady=4, padx=8)
            dot = tk.Label(frame, text="●", fg=MUTED, bg=SURFACE, font=self.fonts["small"])
            dot.pack(side="left", padx=(0, 8))
            lbl = tk.Label(frame, text=step, fg=MUTED, bg=SURFACE, font=self.fonts["body"])
            lbl.pack(side="left")
            detail_lbl = tk.Label(frame, text="", fg=MUTED, bg=SURFACE, font=self.fonts["small"])
            detail_lbl.pack(side="left", padx=(8, 0))
            self.step_frames.append({"name": step, "dot": dot, "lbl": lbl, "detail": detail_lbl, "state": "pending"})
            
    def set_state(self, step_name, state, detail=""):
        for step_data in self.step_frames:
            if step_name in step_data["name"] or step_data["name"].startswith(step_name):
                step_data["state"] = state
                step_data["detail"].configure(text=detail)
                if state == "pending":
                    step_data["dot"].configure(fg=MUTED)
                    step_data["lbl"].configure(fg=MUTED)
                elif state == "running":
                    step_data["dot"].configure(fg=ACCENT)
                    step_data["lbl"].configure(fg=TEXT)
                    self._pulse(step_data["dot"])
                elif state == "done":
                    step_data["dot"].configure(fg=SUCCESS)
                    step_data["lbl"].configure(fg=TEXT)
                elif state == "failed":
                    step_data["dot"].configure(fg=DANGER)
                    step_data["lbl"].configure(fg=DANGER)
                break

    def _pulse(self, dot_widget):
        # Stop pulsing if not running anymore
        for step_data in self.step_frames:
            if step_data["dot"] == dot_widget:
                if step_data["state"] != "running":
                    return
        
        current_color = dot_widget.cget("fg")
        next_color = MUTED if current_color == ACCENT else ACCENT
        dot_widget.configure(fg=next_color)
        self.after(500, self._pulse, dot_widget)

class DarkDialog(tk.Toplevel):
    def __init__(self, parent, title, message, kind="info"):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = False
        
        # Close on Escape
        self.bind("<Escape>", lambda e: self.close())
        
        fonts = get_fonts()
        
        frame = tk.Frame(self, bg=BG, padx=24, pady=24)
        frame.pack(fill="both", expand=True)
        
        msg_lbl = tk.Label(frame, text=message, bg=BG, fg=TEXT, font=fonts["body"], justify="left", wraplength=350)
        msg_lbl.pack(pady=(0, 24))
        
        btn_frame = tk.Frame(frame, bg=BG)
        btn_frame.pack(fill="x")
        
        if kind == "confirm":
            btn_cancel = SecondaryButton(btn_frame, text="Cancel", command=self.close)
            btn_cancel.pack(side="right", padx=(8, 0))
            btn_ok = PrimaryButton(btn_frame, text="OK", command=self.confirm)
            btn_ok.pack(side="right")
        elif kind == "error":
            btn_ok = DangerButton(btn_frame, text="Close", command=self.close)
            btn_ok.pack(side="right")
        else:
            btn_ok = PrimaryButton(btn_frame, text="OK", command=self.close)
            btn_ok.pack(side="right")
            
        self.update_idletasks()
        
        # Center dialog on parent
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")
        
    def close(self):
        self.result = False
        self.destroy()
        
    def confirm(self):
        self.result = True
        self.destroy()
