import tkinter as tk
from tkinter import messagebox
import re
from urllib.parse import urlparse

def scan_url():
    url = entry.get().strip()
    
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL to scan.")
        return

    # Normalize the URL for the parser if the user forgot 'http'
    if not url.startswith('http'):
        url_for_parsing = 'http://' + url
    else:
        url_for_parsing = url

    parsed = urlparse(url_for_parsing)
    score = 0
    red_flags = []

    # 1. Check for IP address in the domain
    if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        score += 3
        red_flags.append("🚨 Uses an IP address instead of a domain name.")

    # 2. Check for the '@' symbol trick
    if '@' in url:
        score += 3
        red_flags.append("🚨 Contains '@' symbol (often used to mask the real destination).")

    # 3. Check for suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'signin']
    found_words = [word for word in suspicious_words if word in url.lower()]
    if found_words:
        score += 2
        red_flags.append(f"🚨 Contains suspicious keywords: {', '.join(found_words)}")

    # 4. Check URL length
    if len(url) > 75:
        score += 1
        red_flags.append("⚠️ URL is unusually long (common in phishing).")

    # 5. Check for HTTPS
    if url.startswith('http://'):
        score += 1
        red_flags.append("⚠️ Uses unencrypted HTTP instead of secure HTTPS.")

    # Determine Safety Status
    if score == 0:
        status = "SAFE 🟢"
        color = "#2ecc71"
    elif score <= 2:
        status = "SUSPICIOUS 🟡"
        color = "#f1c40f"
    else:
        status = "PHISHING RISK 🔴"
        color = "#e74c3c"

    # Update GUI
    lbl_result.config(text=f"Result: {status}", fg=color)
    
    if red_flags:
        lbl_reasons.config(text="Red Flags Detected:\n\n" + "\n".join(red_flags), fg="#ecf0f1")
    else:
        lbl_reasons.config(text="No obvious rule-based red flags detected.", fg="#2ecc71")


# --- GUI Setup ---
root = tk.Tk()
root.title("Phishing URL Scanner")
root.geometry("550x450")
root.configure(bg="#1e272e")

# Title
title_lbl = tk.Label(root, text="Phishing Website Scanner", font=("Arial", 16, "bold"), bg="#1e272e", fg="#00d8d6")
title_lbl.pack(pady=20)

# Input Box
entry = tk.Entry(root, font=("Arial", 14), width=40)
entry.pack(pady=10)
entry.insert(0, "Paste URL here...")

# Clear placeholder text when clicked
def clear_placeholder(event):
    if entry.get() == "Paste URL here...":
        entry.delete(0, tk.END)
entry.bind("<FocusIn>", clear_placeholder)

# Scan Button
btn_scan = tk.Button(root, text="Scan URL", font=("Arial", 12, "bold"), bg="#0fb8ad", fg="white", command=scan_url)
btn_scan.pack(pady=15)

# Result Label
lbl_result = tk.Label(root, text="", font=("Arial", 16, "bold"), bg="#1e272e")
lbl_result.pack(pady=10)

# Reasons / Details Label
lbl_reasons = tk.Label(root, text="", font=("Arial", 11), bg="#1e272e", fg="#d2dae2", justify="left", wraplength=500)
lbl_reasons.pack(pady=10)

root.mainloop()