import platform
import tkinter as tk
from tkinter import ttk, font

# Theme Tokens
BG = "#0D1117"
SURFACE = "#161B22"
ELEVATED = "#1F2630"
BORDER = "#30363D"
TEXT = "#E6EDF3"
MUTED = "#8B949E"
ACCENT = "#58A6FF"
ACCENT_HOVER = "#79B8FF"
SUCCESS = "#3FB950"
DANGER = "#F85149"
WARNING = "#D29922"

def get_fonts():
    families = font.families()
    
    ui_font = "Segoe UI"
    if platform.system() == "Darwin":
        ui_font = "SF Pro Text" if "SF Pro Text" in families else "Helvetica Neue"
    elif platform.system() == "Linux":
        ui_font = "DejaVu Sans"
        
    mono_font = "Consolas"
    if "Menlo" in families:
        mono_font = "Menlo"
    elif "DejaVu Sans Mono" in families:
        mono_font = "DejaVu Sans Mono"

    return {
        "title": (ui_font, 20, "bold"),
        "heading": (ui_font, 14, "bold"),
        "body": (ui_font, 11),
        "small": (ui_font, 9),
        "mono": (mono_font, 10),
    }

def apply_theme(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")
    
    fonts = get_fonts()
    
    # Configure root window background
    root.configure(bg=BG)
    
    # Base Ttk settings
    style.configure(".", background=BG, foreground=TEXT, font=fonts["body"])
    
    # Frames
    style.configure("TFrame", background=BG)
    style.configure("Surface.TFrame", background=SURFACE)
    # Ttk styling doesn't naturally support solid borders easily in 'clam' for frames,
    # so we'll use a tk.Frame with highlightbackground for Card in widgets.py.
    
    # Labels
    style.configure("TLabel", background=BG, foreground=TEXT, font=fonts["body"])
    style.configure("Surface.TLabel", background=SURFACE, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("SurfaceMuted.TLabel", background=SURFACE, foreground=MUTED)
    style.configure("Heading.TLabel", font=fonts["heading"])
    style.configure("Title.TLabel", font=fonts["title"])
    style.configure("Success.TLabel", foreground=SUCCESS)
    style.configure("Danger.TLabel", foreground=DANGER)
    
    # Entry
    style.configure("TEntry", fieldbackground=ELEVATED, foreground=TEXT, insertcolor=TEXT, 
                    borderwidth=1, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
    style.map("TEntry",
        bordercolor=[("focus", ACCENT)],
        lightcolor=[("focus", ACCENT)],
        darkcolor=[("focus", ACCENT)]
    )
    
    # Buttons
    style.configure("TButton", background=ELEVATED, foreground=TEXT, bordercolor=BORDER, 
                    borderwidth=1, focuscolor=ACCENT, font=fonts["body"], padding=(8, 4))
    style.map("TButton",
        background=[("active", BORDER), ("disabled", BG)],
        foreground=[("disabled", MUTED)],
        bordercolor=[("disabled", BG)]
    )
    
    style.configure("Accent.TButton", background=ACCENT, foreground=BG, bordercolor=ACCENT)
    style.map("Accent.TButton",
        background=[("active", ACCENT_HOVER), ("disabled", ELEVATED)],
        bordercolor=[("active", ACCENT_HOVER), ("disabled", ELEVATED)],
        foreground=[("disabled", MUTED)]
    )

    style.configure("Danger.TButton", background=BG, foreground=DANGER, bordercolor=DANGER)
    style.map("Danger.TButton",
        background=[("active", DANGER)],
        foreground=[("active", BG)],
        bordercolor=[("disabled", ELEVATED)]
    )
    
    # Progressbar
    style.configure("TProgressbar", troughcolor=ELEVATED, background=ACCENT, bordercolor=BG, 
                    lightcolor=ACCENT, darkcolor=ACCENT, thickness=4)
    
    # Treeview
    style.configure("Treeview", background=BG, foreground=TEXT, fieldbackground=BG, 
                    bordercolor=BORDER, rowheight=24)
    style.map("Treeview",
        background=[("selected", ELEVATED)],
        foreground=[("selected", ACCENT)]
    )
    style.configure("Treeview.Heading", background=SURFACE, foreground=MUTED, 
                    bordercolor=BORDER, font=fonts["small"])
    
    # Scrollbar
    style.configure("Vertical.TScrollbar", background=SURFACE, troughcolor=BG, 
                    bordercolor=BG, arrowcolor=MUTED)
    style.map("Vertical.TScrollbar", background=[("active", ELEVATED)])
    
    # Checkbutton
    style.configure("TCheckbutton", background=BG, foreground=TEXT, 
                    indicatorcolor=ELEVATED, indicatorforeground=ACCENT)
    style.map("TCheckbutton",
        indicatorcolor=[("pressed", SURFACE), ("disabled", BG)],
        indicatorforeground=[("disabled", MUTED)]
    )
    
    # Notebook
    style.configure("TNotebook", background=BG, tabmargins=[2, 5, 2, 0])
    style.configure("TNotebook.Tab", background=SURFACE, foreground=MUTED, 
                    padding=[10, 2], bordercolor=BORDER)
    style.map("TNotebook.Tab",
        background=[("selected", BG)],
        foreground=[("selected", TEXT)],
        expand=[("selected", [1, 1, 1, 0])]
    )
