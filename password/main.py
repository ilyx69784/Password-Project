# main.py
"""
Main GUI module of the application.
Includes two independent tabs, themes (Dark/Light with Treeview styling),
progress bar, JSON save/load, and table sorting/filtering.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import json
import logging
import threading

from connector import DataSourceConnector
from auditor import SecurityAuditor
import strength_checker as sc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

class ModernAuditorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Enterprise Security & Compliance Auditor")
        self.root.geometry("1100x700")

        self.dark_mode = False
        self.current_results = []
        self.checker = sc.PasswordStrengthChecker()

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_theme()

        self.setup_ui()

    def apply_theme(self):
        if self.dark_mode:
            self.bg_color = "#1e1e1e"
            self.fg_color = "#ffffff"
            self.panel_bg = "#2d2d2d"
            self.tree_bg = "#252526"
            self.tree_fg = "#ffffff"
            self.tree_selected = "#0e639c"
            self.heading_bg = "#333333"
        else:
            self.bg_color = "#f4f6f9"
            self.fg_color = "#333333"
            self.panel_bg = "#ffffff"
            self.tree_bg = "#ffffff"
            self.tree_fg = "#000000"
            self.tree_selected = "#007bff"
            self.heading_bg = "#e9ecef"

        self.root.configure(bg=self.bg_color)
        
        # General style configurations
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.fg_color)
        self.style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        
        # Treeview styles fix for dark mode
        self.style.configure("Treeview", 
            rowheight=26, 
            font=("Segoe UI", 10),
            background=self.tree_bg,
            foreground=self.tree_fg,
            fieldbackground=self.tree_bg
        )
        self.style.configure("Treeview.Heading", 
            font=("Segoe UI", 10, "bold"),
            background=self.heading_bg,
            foreground=self.tree_fg
        )
        self.style.map("Treeview", 
            background=[('selected', self.tree_selected)],
            foreground=[('selected', '#ffffff')]
        )

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def setup_ui(self):
        header_frame = ttk.Frame(self.root, padding="15 15 15 5")
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        ttk.Label(header_frame, text="Security & Compliance Auditor Pro", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Button(header_frame, text="🌓 Toggle Theme", command=self.toggle_theme).pack(side=tk.RIGHT, padx=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill=tk.BOTH, padx=15, pady=10)

        audit_tab = ttk.Frame(notebook, padding=10)
        strength_tab = ttk.Frame(notebook, padding=10)

        notebook.add(audit_tab, text="  Account Audit  ")
        notebook.add(strength_tab, text="  Password Strength Checker  ")

        self.build_audit_tab(audit_tab)
        self.build_strength_tab(strength_tab)

    # --- Tab 1: Account Audit ---
    def build_audit_tab(self, parent):
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        ttk.Button(ctrl_frame, text="▶ Run Scan", command=self.run_scan_threaded).pack(side=tk.LEFT, padx=3)
        ttk.Button(ctrl_frame, text="💾 Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=3)
        ttk.Button(ctrl_frame, text="📁 Save JSON", command=self.save_json).pack(side=tk.LEFT, padx=3)

        ttk.Label(ctrl_frame, text="Status Filter:").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar(value="All")
        filter_cb = ttk.Combobox(ctrl_frame, textvariable=self.filter_var, values=["All", "🟢 Compliant", "🟡 Warning", "🔴 Critical"], state="readonly", width=16)
        filter_cb.pack(side=tk.LEFT)
        filter_cb.bind("<<ComboboxSelected>>", lambda e: self.populate_tree())

        self.progress = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        main_frame = ttk.Frame(parent)
        main_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("User", "Account Type", "Hash Algorithm", "Age (Days)", "Risk Score", "Status")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse")

        widths = [150, 150, 180, 100, 100, 140]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_tree(c, False))
            self.tree.column(col, width=width, anchor=tk.CENTER if col != "User" else tk.W)

        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure("🟢 Compliant", foreground="#28a745")
        self.tree.tag_configure("🟡 Warning", foreground="#ffc107")
        self.tree.tag_configure("🔴 Critical", foreground="#dc3545")

        details_frame = ttk.Frame(parent, padding=(0, 10, 0, 0))
        details_frame.pack(side=tk.BOTTOM, fill=tk.X)

        ttk.Label(details_frame, text="Details for selected account:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.txt_details = tk.Text(details_frame, height=5, font=("Consolas", 10), bg="#2d2d2d", fg="#a9b7c6", relief=tk.FLAT)
        self.txt_details.pack(fill=tk.X, pady=5)
        self.txt_details.insert(tk.END, "Click 'Run Scan' to begin...")
        self.txt_details.config(state=tk.DISABLED)

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

    def run_scan_threaded(self):
        self.progress.start(10)
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        try:
            connector = DataSourceConnector()
            policy = connector.get_system_policy()
            accounts = connector.fetch_accounts()
            breached_db = {"32ED87BDF5FAC7728E709E306CE449F7"}

            auditor = SecurityAuditor(compromised_hashes=breached_db)
            self.current_results = auditor.run_audit(accounts, policy)
            
            self.root.after(0, self.populate_tree)
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Scan complete. Checked: {len(accounts)} accounts."))
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, self.progress.stop)

    def populate_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        selected_filter = self.filter_var.get()
        for res in self.current_results:
            if selected_filter != "All" and res.status != selected_filter:
                continue
            self.tree.insert("", tk.END, values=(
                res.username, res.type, res.algo,
                res.age, res.risk_score, res.status
            ), tags=(res.status,))

    def sort_tree(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            l.sort(key=lambda t: float(t[0]) if t[0].replace('.','',1).isdigit() else t[0], reverse=reverse)
        except Exception:
            l.sort(key=lambda t: t[0], reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def show_details(self, event):
        selected = self.tree.selection()
        if not selected: return
        username = self.tree.item(selected[0])['values'][0]
        acc = next((a for a in self.current_results if a.username == username), None)
        if acc:
            self.txt_details.config(state=tk.NORMAL)
            self.txt_details.delete(1.0, tk.END)
            self.txt_details.insert(tk.END, f"[{acc.status}] User: {acc.username} (Type: {acc.type})\n")
            self.txt_details.insert(tk.END, f"Issues found:\n{acc.issues}")
            self.txt_details.config(state=tk.DISABLED)

    def export_csv(self):
        if not self.current_results:
            messagebox.showwarning("Empty", "Run a scan first!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(["Username", "Type", "Algo", "Age", "Risk", "Status", "Issues"])
                for r in self.current_results:
                    writer.writerow([r.username, r.type, r.algo, r.age, r.risk_score, r.status, r.issues.replace('\n', ' | ')])
            messagebox.showinfo("Saved", f"File saved to: {path}")

    def save_json(self):
        if not self.current_results:
            messagebox.showwarning("Empty", "No data to save!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump([vars(r) for r in self.current_results], f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Saved", f"JSON saved to: {path}")

    # --- Tab 2: Password Strength Checker ---
    def build_strength_tab(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="Enter a password to check:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 4))

        self.pwd_var = tk.StringVar()
        self.pwd_var.trace_add("write", lambda *args: self.check_strength_realtime())
        
        self.pwd_entry = ttk.Entry(input_frame, textvariable=self.pwd_var, show="•", font=("Consolas", 12), width=35)
        self.pwd_entry.grid(row=1, column=0, sticky=tk.W, ipady=3)

        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="Show password", variable=self.show_pwd, command=self.toggle_pwd_visibility).grid(row=1, column=1, padx=10)
        ttk.Button(input_frame, text="📂 Load Dictionary", command=self.load_custom_dictionary).grid(row=1, column=2, padx=5)

        self.strength_bar = ttk.Progressbar(parent, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.strength_bar.pack(fill=tk.X, pady=5)

        summary_frame = ttk.Frame(parent)
        summary_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        self.lbl_entropy = ttk.Label(summary_frame, text="Entropy: 0 bits", font=("Segoe UI", 10, "bold"))
        self.lbl_entropy.pack(side=tk.LEFT, padx=(0, 15))
        self.lbl_rating = ttk.Label(summary_frame, text="Rating: -", font=("Segoe UI", 10, "bold"))
        self.lbl_rating.pack(side=tk.LEFT, padx=(0, 15))
        self.lbl_charset = ttk.Label(summary_frame, text="Charset: -", font=("Segoe UI", 9))
        self.lbl_charset.pack(side=tk.LEFT)

        checks_frame = ttk.Frame(parent)
        checks_frame.pack(expand=True, fill=tk.BOTH, pady=5)

        columns = ("Check", "Status", "Details")
        self.checks_tree = ttk.Treeview(checks_frame, columns=columns, show="headings", selectmode="none")
        self.checks_tree.heading("Check", text="Check")
        self.checks_tree.heading("Status", text="Result")
        self.checks_tree.heading("Details", text="Details")
        self.checks_tree.column("Check", width=200, anchor=tk.W)
        self.checks_tree.column("Status", width=90, anchor=tk.CENTER)
        self.checks_tree.column("Details", width=550, anchor=tk.W)
        self.checks_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.checks_tree.tag_configure("pass", foreground="#28a745")
        self.checks_tree.tag_configure("fail", foreground="#dc3545")

    def toggle_pwd_visibility(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "•")

    def load_custom_dictionary(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    custom_words = {line.strip() for line in f if line.strip()}
                self.checker = sc.PasswordStrengthChecker(custom_dictionary=custom_words)
                messagebox.showinfo("Success", f"Loaded custom words: {len(custom_words)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def check_strength_realtime(self):
        password = self.pwd_var.get()
        for item in self.checks_tree.get_children():
            self.checks_tree.delete(item)

        if not password:
            self.lbl_entropy.config(text="Entropy: 0 bits")
            self.lbl_rating.config(text="Rating: -")
            self.lbl_charset.config(text="Charset: -")
            self.strength_bar['value'] = 0
            return

        entropy, charset_info, results, compliant = self.checker.audit_password(password)
        rating = self.checker.entropy_rating(entropy)

        self.lbl_entropy.config(text=f"Entropy: {entropy:.1f} bits")
        self.lbl_rating.config(text=f"Rating: {rating}")
        
        cs_desc = []
        if charset_info['lower']: cs_desc.append("a-z")
        if charset_info['upper']: cs_desc.append("A-Z")
        if charset_info['digits']: cs_desc.append("0-9")
        if charset_info['symbols']: cs_desc.append("symbols")
        self.lbl_charset.config(text=f"Charset ({charset_info['size']} chars): {', '.join(cs_desc)}")

        self.strength_bar['value'] = min((entropy / 128.0) * 100, 100)

        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            tag = "pass" if r["passed"] else "fail"
            self.checks_tree.insert("", tk.END, values=(r["name"], status, r["message"]), tags=(tag,))

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernAuditorGUI(root)
    root.mainloop()