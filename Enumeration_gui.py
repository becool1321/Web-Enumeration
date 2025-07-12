import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter.ttk import Progressbar
from threading import Thread
import subprocess
import sys

class EnumerationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Enumeration Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg="#2b2b2b")

        title_label = tk.Label(root, text="🌐 Web Enumeration Tool", font=("Helvetica", 18, "bold"), bg="#2b2b2b", fg="#00FF99")
        title_label.pack(pady=10)

        input_frame = tk.Frame(root, bg="#2b2b2b")
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Enter Target URL:", font=("Arial", 12), bg="#2b2b2b", fg="white").grid(row=0, column=0)
        self.url_entry = tk.Entry(input_frame, width=40, font=("Arial", 12))
        self.url_entry.grid(row=0, column=1, padx=10)

        tk.Label(input_frame, text="Port Range (e.g., 1-1000):", font=("Arial", 12), bg="#2b2b2b", fg="white").grid(row=1, column=0)
        self.port_entry = tk.Entry(input_frame, width=40, font=("Arial", 12))
        self.port_entry.insert(0, "1-1000")
        self.port_entry.grid(row=1, column=1, padx=10)

        self.email_var = tk.BooleanVar()
        self.email_checkbox = tk.Checkbutton(input_frame, text="Disable Email Extraction", variable=self.email_var, bg="#2b2b2b", fg="white", selectcolor="#3c3f41")
        self.email_checkbox.grid(row=2, columnspan=2, pady=5)

        start_btn = tk.Button(root, text="🚀 Start Enumeration", command=self.start_enumeration, width=20, font=("Arial", 12, "bold"), bg="#00cc66", fg="black")
        start_btn.pack(pady=10)

        self.output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=30, bg="black", fg="lime", font=("Courier New", 10))
        self.output_box.pack(padx=10, pady=10, expand=True, fill='both')

        self.progress = Progressbar(root, orient=tk.HORIZONTAL, length=900, mode='determinate')
        self.progress.pack(pady=10)

        self.status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#1e1e1e", fg="#ffffff")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        root.grid_rowconfigure(3, weight=1)
        root.grid_columnconfigure(0, weight=1)

    def start_enumeration(self):
        url = self.url_entry.get().strip()
        ports = self.port_entry.get().strip()
        no_emails = self.email_var.get()

        if not url:
            messagebox.showwarning("Input Error", "Please enter a valid URL.")
            return

        args = [sys.executable, "-u", "Enumeration.py", "-u", url, "-p", ports]
        if no_emails:
            args.append("--no-emails")

        self.output_box.delete(1.0, tk.END)
        self.output_box.insert(tk.END, "[*] Starting Enumeration...\n\n")
        self.progress["value"] = 0
        self.status_bar.config(text="Enumeration in progress...")

        thread = Thread(target=self.run_command, args=(args,))
        thread.daemon = True
        thread.start()

    def run_command(self, cmd):
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        total_steps = 9
        step_count = 0

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                self.output_box.insert(tk.END, line)
                self.output_box.see(tk.END)

                if "[+] Detecting technologies..." in line:
                    step_count += 1
                elif "[+] Searching for exploits..." in line:
                    step_count += 1
                elif "[+] Fuzzing directories..." in line:
                    step_count += 1
                elif "[+] Fuzzing subdomains..." in line:
                    step_count += 1
                elif "[+] Fuzzing files..." in line:
                    step_count += 1
                elif "[+] Enumerating DNS..." in line:
                    step_count += 1
                elif "[+] Scanning ports..." in line:
                    step_count += 1
                elif "[+] Gathering WHOIS info..." in line:
                    step_count += 1
                elif "[+] Fetching SSL certificate..." in line:
                    step_count += 1

                progress_value = (step_count / total_steps) * 100
                self.progress["value"] = min(progress_value, 100)
                self.root.update_idletasks()

        self.progress["value"] = 100
        self.status_bar.config(text="Enumeration completed.")
        self.output_box.insert(tk.END, "\n[+] Enumeration Completed.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = EnumerationGUI(root)
    root.mainloop()