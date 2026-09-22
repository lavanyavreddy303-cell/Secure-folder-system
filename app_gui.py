import tkinter as tk
from ui.theme import apply_theme
from ui.app import App

def main():
    root = tk.Tk()
    apply_theme(root)
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
