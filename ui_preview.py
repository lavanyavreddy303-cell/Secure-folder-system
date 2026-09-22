import tkinter as tk
from tkinter import ttk
from ui.theme import apply_theme, BG, SURFACE
from ui.widgets import PrimaryButton, SecondaryButton, DangerButton, Badge, StepIndicator, PipelineTrace

def main():
    root = tk.Tk()
    root.title("Cryptix | Secure Folder System - UI Preview")
    root.geometry("800x600")
    apply_theme(root)
    
    frame = tk.Frame(root, bg=BG, padx=24, pady=24)
    frame.pack(fill="both", expand=True)
    
    # Buttons
    btn_frame = tk.Frame(frame, bg=BG)
    btn_frame.pack(anchor="w", pady=10)
    PrimaryButton(btn_frame, text="Primary").pack(side="left", padx=5)
    SecondaryButton(btn_frame, text="Secondary").pack(side="left", padx=5)
    DangerButton(btn_frame, text="Danger").pack(side="left", padx=5)
    
    btn_dis = PrimaryButton(btn_frame, text="Disabled")
    btn_dis.state(['disabled'])
    btn_dis.pack(side="left", padx=5)
    
    # Badges
    badge_frame = tk.Frame(frame, bg=BG)
    badge_frame.pack(anchor="w", pady=10)
    Badge(badge_frame, "SAFE").pack(side="left", padx=5)
    Badge(badge_frame, "TAMPERED").pack(side="left", padx=5)
    
    # Step indicator
    step_ind = StepIndicator(frame)
    step_ind.pack(anchor="w", pady=20, fill="x")
    step_ind.set_step(1) # Step 2 active
    
    # Trace
    trace = PipelineTrace(frame)
    trace.pack(anchor="w", fill="x", pady=20)
    trace.reset("encrypt")
    trace.set_state("SHA-256 hash created", "done")
    trace.set_state("AES-256 file encrypted", "running", detail="50%")
    trace.set_state("AES key RSA-encrypted", "pending")
    
    root.mainloop()

if __name__ == "__main__":
    main()
