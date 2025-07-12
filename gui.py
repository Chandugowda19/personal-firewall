import subprocess
import csv
from tkinter import messagebox

import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import os

LOG_FILE = "firewall_log.txt"

def read_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return f.read()
    return "[!] No logs yet."

def update_logs():
    text_area.delete(1.0, tk.END)
    logs = read_logs()
    text_area.insert(tk.END, logs)
    root.after(3000, update_logs)  # refresh every 3 seconds

# GUI setup
root = tk.Tk()
root.title("🔥 Personal Firewall Log Monitor")
root.geometry("800x500")

text_area = ScrolledText(root, wrap=tk.WORD, font=("Courier", 10))
text_area.pack(expand=True, fill="both")

update_logs()
root.mainloop()
