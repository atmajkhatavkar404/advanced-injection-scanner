import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import os
import threading
import queue
from datetime import datetime

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import Text, messagebox

# -------------------------
# Load Payloads
# -------------------------
def load_payloads(payload_dir="payloads"):
    payloads = {}
    for filename in os.listdir(payload_dir):
        filepath = os.path.join(payload_dir, filename)

        # Skip directories and non-.txt files
        if not os.path.isfile(filepath) or not filename.endswith(".txt"):
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            payloads[filename.replace(".txt", "")] = [
                line.strip() for line in f if line.strip()
            ]
    return payloads

# -------------------------
# Extract Parameters
# -------------------------
def extract_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)

# -------------------------
# Inject Payloads
# -------------------------
def test_injections(url, payloads, msg_queue, progress_bar, log_file):
    parsed = urlparse(url)
    params = extract_params(url)

    if not params:
        msg = "[!] No parameters found in URL.\n"
        msg_queue.put(("insert", msg))
        log_file.write(msg)
        return

    total_tests = sum(len(plist) * len(params) for plist in payloads.values())
    progress_bar["maximum"] = total_tests
    msg_queue.put(("progress", 0))
    current_test = 0

    vulnerabilities = []

    for p_type, plist in payloads.items():
        msg = f"\n[+] Testing {p_type.upper()} payloads...\n"
        msg_queue.put(("insert", msg))
        log_file.write(msg)

        for param in params.keys():
            for payload in plist:
                test_params = params.copy()
                test_params[param] = [payload]

                new_query = urlencode(test_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                try:
                    r = requests.get(new_url, timeout=5)

                    # Reflected payload detection
                    if payload in r.text:
                        msg = f"[!!] Possible {p_type.upper()} injection on param '{param}' with payload: {payload}\n"
                        msg_queue.put(("insert", msg))
                        log_file.write(msg)
                        vulnerabilities.append((p_type, param, payload, "Reflected"))

                    # Error-based SQLi
                    if p_type == "sqli":
                        sql_errors = [
                            "You have an error in your SQL syntax",
                            "Warning: mysql_fetch",
                            "Unclosed quotation mark after the character string",
                            "quoted string not properly terminated"
                        ]
                        if any(err in r.text for err in sql_errors):
                            msg = f"[!!] SQLi error detected on param '{param}' with payload: {payload}\n"
                            msg_queue.put(("insert", msg))
                            log_file.write(msg)
                            vulnerabilities.append((p_type, param, payload, "Error-based"))

                except requests.exceptions.RequestException as e:
                    msg = f"[x] Request error: {e}\n"
                    msg_queue.put(("insert", msg))
                    log_file.write(msg)

                current_test += 1
                msg_queue.put(("progress", current_test))

    msg = "\n[>] Scan completed.\n"
    msg_queue.put(("insert", msg))
    log_file.write(msg)

    # Summary
    if vulnerabilities:
        summary = "\n[Summary] Detected Vulnerabilities:\n"
        for v in vulnerabilities:
            summary += f"- Type: {v[0].upper()}, Param: {v[1]}, Payload: {v[2]}, Detection: {v[3]}\n"
        msg_queue.put(("insert", summary))
        log_file.write(summary)
    else:
        msg = "[>] No vulnerabilities detected.\n"
        msg_queue.put(("insert", msg))
        log_file.write(msg)

    msg_queue.put(("done", ()))

# -------------------------
# Start Scan
# -------------------------
def start_scan(output_box, progress_bar, url_entry, app):
    target_url = url_entry.get().strip()
    if not target_url:
        messagebox.showerror("Error", "Please enter a target URL.")
        return

    payloads = load_payloads("payloads")
    if not payloads:
        messagebox.showerror("Error", "No payloads found in 'payloads' directory.")
        return

    log_filename = f"scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    msg_queue = queue.Queue()

    def run_scan():
        with open(log_filename, "w", encoding="utf-8") as log_file:
            header = f"=== Injection Scan Log ===\nTarget URL: {target_url}\nTimestamp: {datetime.now()}\n\n"
            log_file.write(header)
            msg_queue.put(("insert", header))

            msg = "Loaded payload types:\n"
            msg_queue.put(("insert", msg))
            log_file.write(msg)
            for p_type in payloads:
                msg = f"- {p_type.upper()}: {len(payloads[p_type])} payloads\n"
                msg_queue.put(("insert", msg))
                log_file.write(msg)
            msg_queue.put(("insert", "\n"))
            log_file.write("\n")

            test_injections(target_url, payloads, msg_queue, progress_bar, log_file)

    threading.Thread(target=run_scan, daemon=True).start()

    def update_gui():
        try:
            while not msg_queue.empty():
                action, args = msg_queue.get_nowait()
                if action == "insert":
                    output_box.insert("end", args)
                    output_box.see("end")
                elif action == "progress":
                    progress_bar["value"] = args
                elif action == "done":
                    messagebox.showinfo("Scan Complete", "Injection scan finished. Check log file for details.")
        except queue.Empty:
            pass
        app.after(100, update_gui)

    update_gui()

# -------------------------
# GUI
# -------------------------
def create_gui():
    app = ttk.Window(themename="superhero")  # dark theme
    app.title("💉 Advanced Injection Scanner")
    app.geometry("1000x750")

    # Header
    header = ttk.Label(app, text="💉 Advanced Injection Scanner", font=("Helvetica", 26, "bold"), bootstyle=PRIMARY)
    header.pack(pady=15)

    subtitle = ttk.Label(app, text="Fast • Accurate • Dark Hacker UI", font=("Helvetica", 14), bootstyle=INFO)
    subtitle.pack(pady=5)

    # Theme selector
    theme_frame = ttk.Frame(app)
    theme_frame.pack(pady=5)
    ttk.Label(theme_frame, text="Theme:", bootstyle=INFO).pack(side="left", padx=5)
    theme_var = ttk.StringVar(value="superhero")

    def change_theme(e=None):
        app.style.theme_use(theme_var.get())

    theme_selector = ttk.Combobox(theme_frame, textvariable=theme_var, values=app.style.theme_names(), width=15)
    theme_selector.bind("<<ComboboxSelected>>", change_theme)
    theme_selector.pack(side="left")

    # Target Input
    frame = ttk.LabelFrame(app, text="Target Configuration", padding=15, bootstyle=PRIMARY)
    frame.pack(fill="x", padx=20, pady=10)

    url_label = ttk.Label(frame, text="Target URL (with parameters):", font=("Helvetica", 12))
    url_label.pack(side="left", padx=5)

    url_entry = ttk.Entry(frame, width=70, font=("Helvetica", 12))
    url_entry.pack(side="left", expand=True, fill="x", padx=5)

    # Buttons
    buttons = ttk.Frame(frame)
    buttons.pack(side="right")

    # Output console
    output_frame = ttk.LabelFrame(app, text="📜 Scan Output & Logs", padding=10, bootstyle=SECONDARY)
    output_frame.pack(fill="both", expand=True, padx=20, pady=10)

    output_box = Text(output_frame, wrap="word", font=("Consolas", 11), height=20,
                      bg="#0d1117", fg="#f8f9fa", insertbackground="white", relief="flat")
    output_box.pack(side="left", fill="both", expand=True)

    scrollbar = ttk.Scrollbar(output_frame, command=output_box.yview, bootstyle="round")
    scrollbar.pack(side="right", fill="y")
    output_box.config(yscrollcommand=scrollbar.set)

    # Progress Bar
    progress_frame = ttk.LabelFrame(app, text="⚡ Progress", padding=10, bootstyle=INFO)
    progress_frame.pack(fill="x", padx=20, pady=10)
    progress_bar = ttk.Progressbar(progress_frame, bootstyle=SUCCESS, mode="determinate")
    progress_bar.pack(fill="x", padx=5, pady=5)

    # Buttons
    ttk.Button(buttons, text="▶ Start Scan", bootstyle=SUCCESS, command=lambda: start_scan(output_box, progress_bar, url_entry, app)).pack(side="left", padx=5)
    ttk.Button(buttons, text="🧹 Clear Output", bootstyle=DANGER, command=lambda: output_box.delete(1.0, "end")).pack(side="left", padx=5)

    app.mainloop()

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    create_gui()
