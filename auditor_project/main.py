# main.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv

from connector import DataSourceConnector
from auditor import SecurityAuditor
import strength_checker as sc


class ModernAuditorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Password Security Auditor")
        self.root.geometry("1050x650")

        # Modern styling setup (no third-party libraries required)
        self.style = ttk.Style()
        self.style.theme_use('clam')  # 'clam' looks more modern than the default theme

        bg_color = "#f4f6f9"
        btn_color = "#007bff"
        self.root.configure(bg=bg_color)

        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground="#333333")
        self.style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6,
                              background=btn_color, foreground="white")
        self.style.map("TButton", background=[('active', '#0056b3')])
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#e9ecef")
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=25)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 8))

        self.current_results = []

        self.setup_ui()

    # ------------------------------------------------------------------
    # Overall layout with tabs
    # ------------------------------------------------------------------
    def setup_ui(self):
        header_frame = ttk.Frame(self.root, padding="20 20 20 10")
        header_frame.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(header_frame, text="Security & Compliance Auditor", style="Title.TLabel").pack(side=tk.LEFT)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill=tk.BOTH, padx=15, pady=10)

        audit_tab = ttk.Frame(notebook, padding=10)
        strength_tab = ttk.Frame(notebook, padding=10)

        notebook.add(audit_tab, text="  Account Audit  ")
        notebook.add(strength_tab, text="  Password Strength Checker  ")

        self.build_audit_tab(audit_tab)
        self.build_strength_tab(strength_tab)

    # ------------------------------------------------------------------
    # Tab 1: account hash audit (original functionality)
    # ------------------------------------------------------------------
    def build_audit_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        ttk.Button(btn_frame, text="▶ Run Scan", command=self.run_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)

        main_frame = ttk.Frame(parent)
        main_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("User", "Account Type", "Hash Algorithm", "Age (Days)", "Risk Score", "Status")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse")

        widths = [150, 150, 200, 100, 100, 150]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.CENTER if col != "User" else tk.W)

        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        details_frame = ttk.Frame(parent, padding=(0, 10, 0, 0))
        details_frame.pack(side=tk.BOTTOM, fill=tk.X)

        ttk.Label(details_frame, text="Issue details (select a row):",
                  font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.txt_details = tk.Text(details_frame, height=5, font=("Consolas", 10),
                                    bg="#2d2d2d", fg="#a9b7c6", relief=tk.FLAT)
        self.txt_details.pack(fill=tk.X, pady=5)
        self.txt_details.insert(tk.END, "Click 'Run Scan' to begin...")
        self.txt_details.config(state=tk.DISABLED)

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

    def run_scan(self):
        connector = DataSourceConnector()
        policy = connector.get_system_policy()
        accounts = connector.fetch_accounts()

        # Simulated breach database (hash of the password "123456" in NTLM)
        breached_db = {"32ED87BDF5FAC7728E709E306CE449F7"}

        auditor = SecurityAuditor(compromised_hashes=breached_db)
        self.current_results = auditor.run_audit(accounts, policy)

        for item in self.tree.get_children():
            self.tree.delete(item)

        for res in self.current_results:
            self.tree.insert("", tk.END, values=(
                res["username"], res["type"], res["algo"],
                res["age"], res["risk_score"], res["status"],
            ))

        self.txt_details.config(state=tk.NORMAL)
        self.txt_details.delete(1.0, tk.END)
        self.txt_details.insert(tk.END, f"Scan complete. Accounts checked: {len(accounts)}\n")
        self.txt_details.insert(
            tk.END,
            f"System policy: Min length={policy.min_length}, Max age={policy.max_age_days} days."
        )
        self.txt_details.config(state=tk.DISABLED)

    def show_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        username = item['values'][0]
        account_data = next((acc for acc in self.current_results if acc["username"] == username), None)

        if account_data:
            self.txt_details.config(state=tk.NORMAL)
            self.txt_details.delete(1.0, tk.END)
            self.txt_details.insert(tk.END, f"[{account_data['status']}] User: {username}\n")
            self.txt_details.insert(tk.END, f"Issues found:\n{account_data['issues']}")
            self.txt_details.config(state=tk.DISABLED)

    def export_csv(self):
        if not self.current_results:
            messagebox.showwarning("Empty", "Run a scan first!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(["Username", "Account Type", "Hash Algo", "Age (Days)", "Risk Score", "Status", "Issues"])
                for res in self.current_results:
                    issues_flat = res["issues"].replace('\n', ' | ')
                    writer.writerow([res["username"], res["type"], res["algo"], res["age"],
                                      res["risk_score"], res["status"], issues_flat])
            messagebox.showinfo("Success", f"Report saved to:\n{file_path}")

    # ------------------------------------------------------------------
    # Tab 2: interactive password strength checker (new functionality)
    # ------------------------------------------------------------------
    def build_strength_tab(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 15))

        ttk.Label(input_frame, text="Enter a password to check:",
                  font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))

        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(input_frame, textvariable=self.pwd_var, show="•",
                                    font=("Consolas", 12), width=40)
        self.pwd_entry.grid(row=1, column=0, sticky=tk.W, ipady=4)
        self.pwd_entry.bind("<Return>", lambda e: self.check_strength())

        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="Show password", variable=self.show_pwd,
                         command=self.toggle_pwd_visibility).grid(row=1, column=1, padx=10)

        ttk.Button(input_frame, text="🔍 Check", command=self.check_strength).grid(row=1, column=2, padx=5)

        # Summary: entropy, rating, overall verdict
        summary_frame = ttk.Frame(parent)
        summary_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        self.lbl_entropy = ttk.Label(summary_frame, text="Entropy: -", font=("Segoe UI", 10, "bold"))
        self.lbl_entropy.pack(side=tk.LEFT, padx=(0, 20))

        self.lbl_rating = ttk.Label(summary_frame, text="Rating: -", font=("Segoe UI", 10, "bold"))
        self.lbl_rating.pack(side=tk.LEFT, padx=(0, 20))

        self.lbl_verdict = ttk.Label(summary_frame, text="Verdict: -", font=("Segoe UI", 11, "bold"))
        self.lbl_verdict.pack(side=tk.LEFT)

        # Detailed check results table
        checks_frame = ttk.Frame(parent)
        checks_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("Check", "Status", "Details")
        self.checks_tree = ttk.Treeview(checks_frame, columns=columns, show="headings", selectmode="none")
        self.checks_tree.heading("Check", text="Check")
        self.checks_tree.heading("Status", text="Result")
        self.checks_tree.heading("Details", text="Details")
        self.checks_tree.column("Check", width=220, anchor=tk.W)
        self.checks_tree.column("Status", width=100, anchor=tk.CENTER)
        self.checks_tree.column("Details", width=500, anchor=tk.W)
        self.checks_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar2 = ttk.Scrollbar(checks_frame, orient=tk.VERTICAL, command=self.checks_tree.yview)
        self.checks_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

        self.checks_tree.tag_configure("pass", foreground="#1e7e34")
        self.checks_tree.tag_configure("fail", foreground="#c82333")

    def toggle_pwd_visibility(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "•")

    def check_strength(self):
        password = self.pwd_var.get()

        for item in self.checks_tree.get_children():
            self.checks_tree.delete(item)

        if not password:
            messagebox.showwarning("Empty", "Enter a password to check.")
            return

        entropy, results, compliant = sc.audit_password(password)

        self.lbl_entropy.config(text=f"Entropy: {entropy:.2f} bits")
        self.lbl_rating.config(text=f"Rating: {sc.entropy_rating(entropy)}")
        if compliant:
            self.lbl_verdict.config(text="Verdict: ✅ Meets policy", foreground="#1e7e34")
        else:
            self.lbl_verdict.config(text="Verdict: ❌ Does not meet policy", foreground="#c82333")

        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            tag = "pass" if r["passed"] else "fail"
            self.checks_tree.insert("", tk.END, values=(r["name"], status, r["message"]), tags=(tag,))


if __name__ == "__main__":
    root = tk.Tk()
    app = ModernAuditorGUI(root)
    root.mainloop()
