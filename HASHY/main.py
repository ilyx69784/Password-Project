# main.py
"""
HASHY - Enterprise Password Security & Compliance Auditor.
GUI designed matching the presentation's cybersecurity aesthetic with Day/Night theme toggle.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import sqlite3
import logging
from pathlib import Path

# Try importing PIL for PNG logo support
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

from connector import DataSourceConnector
from database import Database
from models import AccountType
from auditor import SecurityAuditor
import strength_checker as sc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

class HashyAuditorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HASHY - Enterprise Password Security & Compliance Auditor")
        self.root.geometry("1150x720")

        self.db = Database()
        self.connector = DataSourceConnector(self.db)
        self.current_results = []
        self.dark_mode = True  # Default to presentation dark theme

        # Load logo image if available
        self.logo_img = None
        if PIL_AVAILABLE:
            try:
                logo_path = Path(__file__).resolve().parent / "HASHY.png"
                if logo_path.exists():
                    pil_image = Image.open(logo_path).resize((40, 40), Image.Resampling.LANCZOS)
                    self.logo_img = ImageTk.PhotoImage(pil_image)
            except Exception as e:
                logger.warning(f"Failed to load HASHY.png: {e}")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_theme()

        self.setup_ui()

    def apply_theme(self):
        """Configures UI colors dynamically for Dark (Presentation) or Day/Light mode."""
        if self.dark_mode:
            self.bg_main = "#16192e"
            self.bg_panel = "#1e223f"
            self.fg_primary = "#ffffff"
            self.fg_muted = "#94a3b8"
            self.accent_gold = "#f59e0b"
            self.accent_hover = "#d97706"
            self.tree_bg = "#1e223f"
            self.tree_fg = "#ffffff"
            self.heading_bg = "#252a4a"
            self.text_bg = "#1e223f"
        else:
            self.bg_main = "#f4f6f9"
            self.bg_panel = "#ffffff"
            self.fg_primary = "#1e293b"
            self.fg_muted = "#64748b"
            self.accent_gold = "#d97706"
            self.accent_hover = "#b45309"
            self.tree_bg = "#ffffff"
            self.tree_fg = "#0f172a"
            self.heading_bg = "#e2e8f0"
            self.text_bg = "#ffffff"
        
        self.root.configure(bg=self.bg_main)

        self.style.configure("TFrame", background=self.bg_main)
        self.style.configure("Panel.TFrame", background=self.bg_panel)
        
        self.style.configure("TLabel", background=self.bg_main, foreground=self.fg_primary, font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), foreground=self.accent_gold, background=self.bg_main)
        self.style.configure("Subtitle.TLabel", font=("Segoe UI", 11, "bold"), foreground=self.fg_muted, background=self.bg_main)

        self.style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8, background=self.accent_gold, foreground="#ffffff" if not self.dark_mode else "#16192e", borderwidth=0)
        self.style.map("TButton", background=[('active', self.accent_hover)], foreground=[('active', '#ffffff')])

        self.style.configure("TNotebook", background=self.bg_main, borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 10), background=self.bg_panel, foreground=self.fg_muted)
        self.style.map("TNotebook.Tab", background=[('selected', self.accent_gold)], foreground=[('selected', '#ffffff' if not self.dark_mode else '#16192e')])

        self.style.configure("Treeview", 
            rowheight=28, 
            font=("Segoe UI", 10),
            background=self.tree_bg,
            foreground=self.tree_fg,
            fieldbackground=self.tree_bg,
            borderwidth=0
        )
        self.style.configure("Treeview.Heading", 
            font=("Segoe UI", 10, "bold"),
            background=self.heading_bg,
            foreground=self.tree_fg,
            relief="flat"
        )
        self.style.map("Treeview", 
            background=[('selected', self.accent_gold)],
            foreground=[('selected', '#ffffff' if not self.dark_mode else '#16192e')]
        )

    def toggle_theme(self):
        """Switches between Dark Mode (Presentation) and Day/Light Mode."""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        # Re-render or update components if needed
        self.root.update_idletasks()

    def setup_ui(self):
        header_frame = ttk.Frame(self.root, padding="20 20 20 10")
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        if self.logo_img:
            logo_label = ttk.Label(header_frame, image=self.logo_img)
            logo_label.pack(side=tk.LEFT, padx=(0, 12))

        title_box = ttk.Frame(header_frame)
        title_box.pack(side=tk.LEFT)
        ttk.Label(title_box, text="HASHY", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(title_box, text="Password Security Checks & Compliance Auditor Suite", style="Subtitle.TLabel").pack(anchor=tk.W)

        # Theme toggle button in header
        ttk.Button(header_frame, text="🌓 Toggle Theme", command=self.toggle_theme).pack(side=tk.RIGHT, padx=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill=tk.BOTH, padx=15, pady=10)

        audit_tab = ttk.Frame(notebook, padding=15)
        strength_tab = ttk.Frame(notebook, padding=15)
        database_tab = ttk.Frame(notebook, padding=15)

        notebook.add(audit_tab, text="  Account Audit  ")
        notebook.add(strength_tab, text="  Password Checker  ")
        notebook.add(database_tab, text="  Database (auditor.db)  ")

        self.build_audit_tab(audit_tab)
        self.build_strength_tab(strength_tab)
        self.build_database_tab(database_tab)

    def build_audit_tab(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 12))

        ttk.Button(btn_frame, text="▶ Run Security Scan", command=self.run_scan).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="💾 Export CSV Report", command=self.export_csv).pack(side=tk.LEFT, padx=8)

        main_frame = ttk.Frame(parent)
        main_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("User", "Account Type", "Hash Algorithm", "Age (Days)", "Risk Score", "Status")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", selectmode="browse")

        widths = [160, 160, 220, 110, 110, 160]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.CENTER if col != "User" else tk.W)

        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure("🟢 Compliant", foreground="#10b981" if not self.dark_mode else "#34d399")
        self.tree.tag_configure("🟡 Warning", foreground="#d97706" if not self.dark_mode else "#fbbf24")
        self.tree.tag_configure("🔴 Critical", foreground="#dc2626" if not self.dark_mode else "#f87171")

        details_frame = ttk.Frame(parent, padding=(0, 12, 0, 0))
        details_frame.pack(side=tk.BOTTOM, fill=tk.X)

        ttk.Label(details_frame, text="Vulnerability Details & Remediation (Select an account):",
                  font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 4))
        
        self.txt_details = tk.Text(details_frame, height=5, font=("Consolas", 10),
                                    bg="#1e223f", fg="#f87171", relief=tk.FLAT, bd=0)
        self.txt_details.pack(fill=tk.X, ipady=4)
        self.txt_details.insert(tk.END, "Click 'Run Security Scan' to analyze accounts from auditor.db...")
        self.txt_details.config(state=tk.DISABLED)

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

    def run_scan(self):
        policy = self.connector.get_system_policy()
        accounts = self.connector.fetch_accounts()
        breached_db = self.connector.fetch_compromised_hashes()

        auditor = SecurityAuditor(compromised_hashes=breached_db)
        self.current_results = auditor.run_audit(accounts, policy)
        run_id = self.db.save_audit(self.current_results)
        self.refresh_audit_history()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for res in self.current_results:
            self.tree.insert("", tk.END, values=(
                res["username"], res["type"], res["algo"],
                res["age"], res["risk_score"], res["status"],
            ), tags=(res["status"],))

        self.txt_details.config(state=tk.NORMAL)
        self.txt_details.delete(1.0, tk.END)
        self.txt_details.insert(tk.END, f"Scan #{run_id} completed. Accounts checked: {len(accounts)}\n")
        self.txt_details.insert(
            tk.END,
            f"Policy: Min length = {policy.min_length} | Max age = {policy.max_age_days} days."
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
            messagebox.showwarning("Empty", "Run a security scan first!")
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

    def build_strength_tab(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 15))

        ttk.Label(input_frame, text="Test Password Entropy & NIST Compliance:",
                  font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))

        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(input_frame, textvariable=self.pwd_var, show="•",
                                    font=("Consolas", 12), width=40)
        self.pwd_entry.grid(row=1, column=0, sticky=tk.W, ipady=4)
        self.pwd_entry.bind("<Return>", lambda e: self.check_strength())

        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="Show password", variable=self.show_pwd,
                         command=self.toggle_pwd_visibility).grid(row=1, column=1, padx=15)

        ttk.Button(input_frame, text="🔍 Analyze", command=self.check_strength).grid(row=1, column=2, padx=5)

        summary_frame = ttk.Frame(parent)
        summary_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 12))

        self.lbl_entropy = ttk.Label(summary_frame, text="Entropy: —", font=("Segoe UI", 10, "bold"))
        self.lbl_entropy.pack(side=tk.LEFT, padx=(0, 25))

        self.lbl_rating = ttk.Label(summary_frame, text="Rating: —", font=("Segoe UI", 10, "bold"))
        self.lbl_rating.pack(side=tk.LEFT, padx=(0, 25))

        self.lbl_verdict = ttk.Label(summary_frame, text="Verdict: —", font=("Segoe UI", 11, "bold"))
        self.lbl_verdict.pack(side=tk.LEFT)

        checks_frame = ttk.Frame(parent)
        checks_frame.pack(expand=True, fill=tk.BOTH)

        columns = ("Check", "Status", "Details")
        self.checks_tree = ttk.Treeview(checks_frame, columns=columns, show="headings", selectmode="none")
        self.checks_tree.heading("Check", text="Security Check")
        self.checks_tree.heading("Status", text="Result")
        self.checks_tree.heading("Details", text="Description")
        self.checks_tree.column("Check", width=220, anchor=tk.W)
        self.checks_tree.column("Status", width=100, anchor=tk.CENTER)
        self.checks_tree.column("Details", width=550, anchor=tk.W)
        self.checks_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar2 = ttk.Scrollbar(checks_frame, orient=tk.VERTICAL, command=self.checks_tree.yview)
        self.checks_tree.configure(yscroll=scrollbar2.set)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)

        self.checks_tree.tag_configure("pass", foreground="#10b981" if not self.dark_mode else "#34d399")
        self.checks_tree.tag_configure("fail", foreground="#dc2626" if not self.dark_mode else "#f87171")

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
        rating = sc.entropy_rating(entropy)
        
        self.db.save_strength_check(
            entropy, rating, compliant,
            sum(1 for r in results if r["passed"]), len(results)
        )
        self.refresh_strength_history()

        self.lbl_entropy.config(text=f"Entropy: {entropy:.2f} bits")
        self.lbl_rating.config(text=f"Rating: {rating}")
        if compliant:
            self.lbl_verdict.config(text="Verdict: ✅ Meets policy", foreground="#10b981" if not self.dark_mode else "#34d399")
        else:
            self.lbl_verdict.config(text="Verdict: ❌ Does not meet policy", foreground="#dc2626" if not self.dark_mode else "#f87171")

        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            tag = "pass" if r["passed"] else "fail"
            self.checks_tree.insert("", tk.END, values=(r["name"], status, r["message"]), tags=(tag,))

    def build_database_tab(self, parent):
        ttk.Label(parent, text="SQLite Database: auditor.db (Managed Persistence)",
                  font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 8))
        
        tabs = ttk.Notebook(parent)
        tabs.pack(expand=True, fill=tk.BOTH)
        
        accounts_tab = ttk.Frame(tabs, padding=10)
        audits_tab = ttk.Frame(tabs, padding=10)
        strength_tab = ttk.Frame(tabs, padding=10)
        
        tabs.add(accounts_tab, text="Accounts")
        tabs.add(audits_tab, text="Audit History")
        tabs.add(strength_tab, text="Strength History")

        account_buttons = ttk.Frame(accounts_tab)
        account_buttons.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(account_buttons, text="🔄 Refresh", command=self.refresh_accounts).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(account_buttons, text="➕ Add Demo Account", command=self.add_demo_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(account_buttons, text="❌ Delete Selected", command=self.delete_selected_account).pack(side=tk.LEFT, padx=5)
        
        self.account_tree = self.make_table(
            accounts_tab, ("Username", "Account Type", "Age (days)", "Enabled"),
            (240, 250, 140, 120)
        )
        ttk.Label(accounts_tab,
                  text="Demo accounts loaded from SQLite. Passwords and sensitive data remain secure.",
                  foreground="#64748b" if not self.dark_mode else "#94a3b8").pack(anchor=tk.W, pady=6)

        audit_buttons = ttk.Frame(audits_tab)
        audit_buttons.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(audit_buttons, text="🔄 Refresh History", command=self.refresh_audit_history).pack(side=tk.LEFT)
        ttk.Label(audit_buttons, text="💡 Double-click a run to inspect saved results.", foreground=self.fg_muted).pack(side=tk.LEFT, padx=15)
        
        self.history_tree = self.make_table(
            audits_tab, ("Run ID", "Timestamp", "Checked", "Critical", "Warning", "Compliant"),
            (80, 260, 100, 100, 100, 100)
        )
        self.history_tree.bind("<Double-1>", self.show_saved_audit)

        strength_buttons = ttk.Frame(strength_tab)
        strength_buttons.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(strength_buttons, text="🔄 Refresh History", command=self.refresh_strength_history).pack(side=tk.LEFT)
        ttk.Label(strength_tab, text="🔒 Only numerical metrics are saved; typed passwords are never logged.").pack(anchor=tk.W)
        
        self.strength_history_tree = self.make_table(
            strength_tab, ("ID", "Timestamp", "Entropy", "Rating", "Compliant", "Checks Passed"),
            (70, 260, 110, 150, 120, 130)
        )

        self.refresh_accounts()
        self.refresh_audit_history()
        self.refresh_strength_history()

    @staticmethod
    def make_table(parent, columns, widths):
        frame = ttk.Frame(parent)
        frame.pack(expand=True, fill=tk.BOTH)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for name, width in zip(columns, widths):
            tree.heading(name, text=name)
            tree.column(name, width=width, anchor=tk.W)
        tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    @staticmethod
    def clear_table(tree):
        for item in tree.get_children():
            tree.delete(item)

    def refresh_accounts(self):
        self.clear_table(self.account_tree)
        for acc in self.db.get_accounts():
            self.account_tree.insert("", tk.END, values=(
                acc["username"], acc["type"].value,
                acc["password_age_days"], "Yes" if acc["enabled"] else "No"
            ))

    def add_demo_account(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Demo Account")
        dialog.geometry("520x300")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.bg_main)
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        username = tk.StringVar()
        account_type = tk.StringVar(value=AccountType.STANDARD.value)
        age = tk.StringVar(value="0")
        demo_hash = tk.StringVar(value="$6$demo$synthesized-example-only")
        
        inputs = [
            ("Username", ttk.Entry(frame, textvariable=username, width=38)),
            ("Account type", ttk.Combobox(frame, textvariable=account_type,
                                          values=[t.value for t in AccountType],
                                          state="readonly", width=35)),
            ("Password age (days)", ttk.Entry(frame, textvariable=age, width=38)),
            ("Simulated hash", ttk.Entry(frame, textvariable=demo_hash, width=38)),
        ]
        for index, (label, widget) in enumerate(inputs):
            ttk.Label(frame, text=label).grid(row=index, column=0, sticky=tk.W, pady=6)
            widget.grid(row=index, column=1, sticky=tk.W, padx=10, pady=6)
            
        ttk.Label(frame, text="For educational demo data only.", foreground="#dc2626" if not self.dark_mode else "#f87171").grid(row=4, column=0, columnspan=2, pady=10)

        def submit():
            try:
                if not demo_hash.get().strip():
                    raise ValueError("Enter a simulated hash")
                self.db.add_account(username.get(), account_type.get(),
                                    age.get(), demo_hash.get())
            except (ValueError, sqlite3.IntegrityError) as exc:
                messagebox.showerror("Error", str(exc), parent=dialog)
                return
            self.refresh_accounts()
            dialog.destroy()

        ttk.Button(frame, text="Save Account", command=submit).grid(row=5, column=1, sticky=tk.E, pady=5)

    def delete_selected_account(self):
        selection = self.account_tree.selection()
        if not selection:
            messagebox.showinfo("Select Account", "Choose an account first.")
            return
        username = self.account_tree.item(selection[0])["values"][0]
        if messagebox.askyesno("Confirm Deletion", f"Delete demo account '{username}'?"):
            self.db.delete_account(username)
            self.refresh_accounts()

    def refresh_audit_history(self):
        self.clear_table(self.history_tree)
        for run in self.db.get_audit_runs():
            self.history_tree.insert("", tk.END, values=(
                run["id"], run["created_at"], run["accounts_checked"],
                run["critical_count"], run["warning_count"], run["compliant_count"]
            ))

    def show_saved_audit(self, event=None):
        selection = self.history_tree.selection()
        if not selection:
            return
        run_id = int(self.history_tree.item(selection[0])["values"][0])
        saved = self.db.get_audit_results(run_id)
        
        window = tk.Toplevel(self.root)
        window.title(f"Audit Run #{run_id} Report")
        window.geometry("950x550")
        window.configure(bg=self.bg_main)
        
        frame = ttk.Frame(window, padding=15)
        frame.pack(expand=True, fill=tk.BOTH)
        
        tree = self.make_table(
            frame, ("Username", "Algorithm", "Age", "Risk Score", "Status"),
            (180, 240, 70, 90, 180)
        )
        details = tk.Text(frame, height=7, wrap=tk.WORD, font=("Consolas", 10), bg=self.bg_panel, fg="#dc2626" if not self.dark_mode else "#f87171", bd=0)
        details.pack(fill=tk.X, pady=(12, 0))
        
        for index, result in enumerate(saved):
            tree.insert("", tk.END, iid=str(index), values=(
                result["username"], result["hash_algorithm"],
                result["age_days"], result["risk_score"], result["status"]
            ))

        def select_saved_result(event=None):
            sel = tree.selection()
            if not sel:
                return
            res = saved[int(sel[0])]
            details.delete("1.0", tk.END)
            details.insert(tk.END, f"User: {res['username']}\nIssues:\n{res['issues']}")

        tree.bind("<<TreeviewSelect>>", select_saved_result)

    def refresh_strength_history(self):
        self.clear_table(self.strength_history_tree)
        for item in self.db.get_strength_checks():
            self.strength_history_tree.insert("", tk.END, values=(
                item["id"], item["created_at"], f"{item['entropy']:.2f}",
                item["rating"], "Yes" if item["compliant"] else "No",
                f"{item['checks_passed']}/{item['checks_total']}"
            ))


if __name__ == "__main__":
    root = tk.Tk()
    app = HashyAuditorGUI(root)
    root.mainloop()