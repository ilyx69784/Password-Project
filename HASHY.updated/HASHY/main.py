# main.py
"""
HASHY: Password Security & Compliance Auditor (educational build).

Tab 1  Account Audit      scans stored hashes (connector -> auditor -> SQLite)
Tab 2  Password Strength  interactive checker driven by the SAME stored policy
Tab 3  Database           accounts, policy, breach data, history, trends,
                          backups and integrity checks

Synthetic data only. See README.md for scope and limitations.
"""
import csv
import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

import strength_checker as sc
from auditor import SecurityAuditor
from connector import DataSourceConnector
from database import Database, mask_hash, safe_csv_cell
from models import DECLARABLE_FORMATS, AccountType, SystemPolicy, TrafficLight
from sample_data import synthetic_crypt

APP_NAME = "HASHY"
ASSETS = Path(__file__).resolve().parent / "assets"

# Palettes derived from the HASHY logo (#1e1b2e navy, #f5b942 gold, #faf7f2 cream).
THEMES = {
    "dark": dict(bg="#1e1b2e", surface="#262238", field="#2f2a45", fg="#faf7f2",
                 muted="#c4bfd6", accent="#f5b942", accent_fg="#1e1b2e",
                 accent_active="#ffcb66", border="#463f66", select="#4a4470",
                 select_fg="#faf7f2", heading="#332d4d", text_bg="#15131f",
                 text_fg="#e9e5f5", critical="#ff7a7a", warning="#f5b942",
                 ok="#6fdc9a", inactive="#a9a5b8", grid="#3a3455", bar="#7d3a52"),
    "light": dict(bg="#f6f4ef", surface="#ffffff", field="#ffffff", fg="#1e1b2e",
                  muted="#4f4a63", accent="#1e1b2e", accent_fg="#faf7f2",
                  accent_active="#38325a", border="#c9c4d6", select="#f5d58c",
                  select_fg="#1e1b2e", heading="#ebe7f2", text_bg="#fbfaf7",
                  text_fg="#1e1b2e", critical="#b3261e", warning="#8a5a00",
                  ok="#1e6e34", inactive="#5f5b70", grid="#ddd8e6", bar="#f0b9b3"),
}
STATUS_TAGS = {
    TrafficLight.RED.value: "critical", TrafficLight.YELLOW.value: "warning",
    TrafficLight.GREEN.value: "ok", TrafficLight.INACTIVE.value: "inactive",
}
SHORTCUTS = [
    ("Ctrl+R", "Run account scan"), ("Ctrl+E", "Export current scan to CSV"),
    ("Ctrl+B", "Back up database"), ("Ctrl+T", "Toggle dark / light theme"),
    ("Ctrl+1 / 2 / 3", "Switch main tab"), ("Ctrl+N", "Add demo account (Database tab)"),
    ("Delete", "Delete selected account (Accounts table)"),
    ("Enter / double-click", "Open selected saved run"),
    ("F5", "Refresh tables"), ("Esc", "Close dialog"), ("F1", "Show this help"),
]


def _tags(tag):
    return (tag,) if tag else ()


class ModernAuditorGUI:
    def __init__(self, root, db=None):
        self.root = root
        self.root.title(f"{APP_NAME} | Password Security & Compliance Auditor")
        self.root.geometry("1180x760")
        self.root.minsize(980, 620)

        self.db = db or Database()
        self.connector = DataSourceConnector(self.db)
        self.current_results = []
        self.text_widgets, self.canvases, self.trees = [], [], []
        self.theme_name = self.db.get_setting("theme", "dark")
        if self.theme_name not in THEMES:
            self.theme_name = "dark"

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._load_images()
        self.setup_ui()
        self.apply_theme(self.theme_name)
        self.bind_shortcuts()
        self.set_status("Ready. Synthetic demo data only: never enter real credentials.")

    # ------------------------------------------------------------------
    # Images, theme, status
    # ------------------------------------------------------------------
    def _load_images(self):
        self.logo_img = self.icon_img = None
        try:
            self.logo_img = tk.PhotoImage(file=str(ASSETS / "hashy_logo_64.png"))
            self.icon_img = tk.PhotoImage(file=str(ASSETS / "hashy_icon_32.png"))
            self.root.iconphoto(True, self.icon_img)
        except tk.TclError:
            pass  # missing assets must never stop the app

    @property
    def colors(self):
        return THEMES[self.theme_name]

    def apply_theme(self, name):
        self.theme_name = name
        c = THEMES[name]
        s = self.style
        base = ("Segoe UI", 10)
        self.root.configure(bg=c["bg"])
        s.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field"],
                    bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                    troughcolor=c["surface"], selectbackground=c["select"],
                    selectforeground=c["select_fg"], insertcolor=c["fg"], font=base,
                    focuscolor=c["accent"])
        s.configure("TFrame", background=c["bg"])
        s.configure("Card.TFrame", background=c["surface"])
        s.configure("TLabel", background=c["bg"], foreground=c["fg"])
        s.configure("Muted.TLabel", foreground=c["muted"])
        s.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        s.configure("Sub.TLabel", foreground=c["muted"], font=("Segoe UI", 10))
        s.configure("Bold.TLabel", font=("Segoe UI", 10, "bold"))
        s.configure("Warn.TLabel", foreground=c["critical"])
        s.configure("TButton", background=c["accent"], foreground=c["accent_fg"],
                    font=("Segoe UI", 10, "bold"), padding=(10, 5), borderwidth=1)
        s.map("TButton", background=[("active", c["accent_active"]), ("disabled", c["border"])],
              foreground=[("disabled", c["muted"])])
        s.configure("Ghost.TButton", background=c["surface"], foreground=c["fg"])
        s.map("Ghost.TButton", background=[("active", c["heading"])])
        s.configure("TEntry", fieldbackground=c["field"], foreground=c["fg"])
        s.configure("TSpinbox", fieldbackground=c["field"], foreground=c["fg"],
                    arrowcolor=c["fg"])
        s.configure("TCombobox", fieldbackground=c["field"], foreground=c["fg"],
                    arrowcolor=c["fg"])
        s.map("TCombobox", fieldbackground=[("readonly", c["field"])],
              foreground=[("readonly", c["fg"])])
        self.root.option_add("*TCombobox*Listbox.background", c["field"])
        self.root.option_add("*TCombobox*Listbox.foreground", c["fg"])
        s.configure("TCheckbutton", background=c["bg"], foreground=c["fg"])
        s.map("TCheckbutton", background=[("active", c["bg"])])
        s.configure("TLabelframe", background=c["bg"])
        s.configure("TLabelframe.Label", background=c["bg"], foreground=c["muted"],
                    font=("Segoe UI", 10, "bold"))
        s.configure("TNotebook", background=c["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", background=c["surface"], foreground=c["muted"],
                    padding=(16, 7), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", c["accent"])],
              foreground=[("selected", c["accent_fg"])])
        s.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                    foreground=c["fg"], rowheight=26, font=base)
        s.map("Treeview", background=[("selected", c["select"])],
              foreground=[("selected", c["select_fg"])])
        s.configure("Treeview.Heading", background=c["heading"], foreground=c["fg"],
                    font=("Segoe UI", 10, "bold"), relief="flat")
        s.map("Treeview.Heading", background=[("active", c["border"])])
        s.configure("Vertical.TScrollbar", background=c["heading"], arrowcolor=c["fg"])
        s.configure("Status.TLabel", background=c["surface"], foreground=c["fg"],
                    padding=(12, 5))

        self.trees = [t for t in self.trees if t.winfo_exists()]
        self.text_widgets = [t for t in self.text_widgets if t.winfo_exists()]
        for tree in self.trees:
            for tag in ("critical", "warning", "ok", "inactive"):
                tree.tag_configure(tag, foreground=c[tag])
            tree.tag_configure("pass", foreground=c["ok"])
            tree.tag_configure("fail", foreground=c["critical"])
        for widget in self.text_widgets:
            widget.configure(bg=c["text_bg"], fg=c["text_fg"], insertbackground=c["fg"],
                             selectbackground=c["select"], selectforeground=c["select_fg"],
                             highlightbackground=c["border"], highlightcolor=c["accent"])
        for top in self.root.winfo_children():
            if isinstance(top, tk.Toplevel):
                top.configure(bg=c["bg"])
        if hasattr(self, "theme_btn"):
            self.theme_btn.configure(text="☀ Light theme" if name == "dark" else "🌙 Dark theme")
        self.draw_trend()

    def toggle_theme(self, event=None):
        new = "light" if self.theme_name == "dark" else "dark"
        self.apply_theme(new)
        self.db.set_setting("theme", new)
        self.set_status(f"{new.capitalize()} theme applied (saved for next start).")

    def set_status(self, text, level="info"):
        prefix = {"info": "ℹ", "ok": "✔", "warn": "⚠", "error": "✖"}[level]
        colour = {"info": "fg", "ok": "ok", "warn": "warning", "error": "critical"}[level]
        self.status.configure(text=f"{prefix}  {text}", foreground=self.colors[colour])

    def error(self, title, exc, parent=None):
        messagebox.showerror(title, str(exc), parent=parent or self.root)
        self.set_status(f"{title}: {exc}", "error")

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def setup_ui(self):
        self.build_menu()
        header = ttk.Frame(self.root, padding="18 14 18 6")
        header.pack(side=tk.TOP, fill=tk.X)
        if self.logo_img:
            ttk.Label(header, image=self.logo_img).pack(side=tk.LEFT, padx=(0, 12))
        titles = ttk.Frame(header)
        titles.pack(side=tk.LEFT)
        ttk.Label(titles, text=APP_NAME, style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(titles, text="Password Security & Compliance Auditor · educational build, "
                               "synthetic data only", style="Sub.TLabel").pack(anchor=tk.W)
        self.theme_btn = ttk.Button(header, style="Ghost.TButton", command=self.toggle_theme)
        self.theme_btn.pack(side=tk.RIGHT)

        self.status = ttk.Label(self.root, style="Status.TLabel", anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=14, pady=(4, 10))
        tabs = [ttk.Frame(self.notebook, padding=10) for _ in range(3)]
        for frame, label in zip(tabs, ("Account Audit", "Password Strength", "Database")):
            self.notebook.add(frame, text=f"  {label}  ", underline=2)
        self.notebook.enable_traversal()
        self.build_audit_tab(tabs[0])
        self.build_strength_tab(tabs[1])
        self.build_database_tab(tabs[2])

    def build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Run scan", accelerator="Ctrl+R", command=self.run_scan)
        file_menu.add_command(label="Export current scan…", accelerator="Ctrl+E",
                              command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Back up database", accelerator="Ctrl+B",
                              command=self.backup_db)
        file_menu.add_command(label="Restore from backup…", command=self.restore_db)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", accelerator="Ctrl+Q", command=self.root.destroy)
        view_menu = tk.Menu(menubar, tearoff=False)
        view_menu.add_command(label="Toggle theme", accelerator="Ctrl+T",
                              command=self.toggle_theme)
        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="Keyboard shortcuts", accelerator="F1",
                              command=self.show_shortcuts)
        help_menu.add_command(label="Scope & limitations", command=self.show_about)
        menubar.add_cascade(label="File", menu=file_menu, underline=0)
        menubar.add_cascade(label="View", menu=view_menu, underline=0)
        menubar.add_cascade(label="Help", menu=help_menu, underline=0)
        self.root.configure(menu=menubar)

    def bind_shortcuts(self):
        b = self.root.bind_all
        b("<Control-r>", lambda e: self.run_scan())
        b("<Control-e>", lambda e: self.export_csv())
        b("<Control-b>", lambda e: self.backup_db())
        b("<Control-t>", self.toggle_theme)
        b("<Control-q>", lambda e: self.root.destroy())
        b("<Control-n>", lambda e: self.add_demo_account())
        b("<F1>", lambda e: self.show_shortcuts())
        b("<F5>", lambda e: self.refresh_all())
        for i in range(3):
            b(f"<Control-Key-{i + 1}>", lambda e, i=i: self.notebook.select(i))

    def make_table(self, parent, columns, widths, height=None):
        frame = ttk.Frame(parent)
        frame.pack(expand=True, fill=tk.BOTH)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse",
                            height=height or 10)
        for name, width in zip(columns, widths):
            tree.heading(name, text=name)
            tree.column(name, width=width, anchor=tk.W, stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)       # fixed: full option name
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.trees.append(tree)
        return tree

    def make_text(self, parent, height=6, **kw):
        frame = ttk.Frame(parent)
        text = tk.Text(frame, height=height, wrap=tk.WORD, font=("Consolas", 10),
                       relief=tk.FLAT, padx=8, pady=6, highlightthickness=1, **kw)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.text_widgets.append(text)
        return frame, text

    @staticmethod
    def set_text(widget, content):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content)
        widget.config(state=tk.DISABLED)

    @staticmethod
    def clear_table(tree):
        tree.delete(*tree.get_children())

    def make_dialog(self, title, geometry=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=self.colors["bg"])
        if geometry:
            dialog.geometry(geometry)
        dialog.transient(self.root)
        dialog.bind("<Escape>", lambda e: dialog.destroy())
        dialog.after(10, dialog.grab_set)
        return dialog

    # ------------------------------------------------------------------
    # Tab 1: account audit
    # ------------------------------------------------------------------
    def build_audit_tab(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))
        ttk.Button(bar, text="▶ Run Scan  (Ctrl+R)", command=self.run_scan).pack(side=tk.LEFT)
        ttk.Button(bar, text="💾 Export CSV  (Ctrl+E)", style="Ghost.TButton",
                   command=self.export_csv).pack(side=tk.LEFT, padx=8)
        self.summary_lbl = ttk.Label(bar, text="No scan yet.", style="Bold.TLabel")
        self.summary_lbl.pack(side=tk.RIGHT)

        table_area = ttk.Frame(parent)
        table_area.pack(expand=True, fill=tk.BOTH)
        self.tree = self.make_table(
            table_area, ("User", "Account Type", "Hash Algorithm", "Age (days)", "Enabled",
                         "Risk", "Status"), (150, 130, 300, 90, 75, 60, 130))
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        details = ttk.Frame(parent, padding=(0, 8, 0, 0))
        details.pack(side=tk.BOTTOM, fill=tk.X)
        details.columnconfigure(0, weight=1)
        details.columnconfigure(1, weight=1)
        ttk.Label(details, text="Findings", style="Bold.TLabel").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(details, text="Remediation guidance", style="Bold.TLabel").grid(
            row=0, column=1, sticky=tk.W, padx=(10, 0))
        f1, self.txt_details = self.make_text(details, height=7)
        f2, self.txt_remediation = self.make_text(details, height=7)
        f1.grid(row=1, column=0, sticky="nsew")
        f2.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        self.set_text(self.txt_details, "Press Run Scan (Ctrl+R) to audit the accounts in the "
                                        "database, then select a row.")
        self.set_text(self.txt_remediation, "")

    def run_scan(self):
        try:
            policy = self.connector.get_system_policy()
            accounts = self.connector.fetch_accounts()
            auditor = SecurityAuditor(self.connector.fetch_compromised_hashes())
            self.current_results = auditor.run_audit(accounts, policy)
            run_id = self.db.save_audit(self.current_results)
        except (sqlite3.Error, RuntimeError, ValueError) as exc:
            self.error("Scan failed", exc)
            return
        self.clear_table(self.tree)
        for r in self.current_results:
            self.tree.insert("", tk.END, iid=r["username"], tags=(STATUS_TAGS[r["status"]],),
                             values=(r["username"], r["type"], r["algo"], r["age"],
                                     "Yes" if r["enabled"] else "No", r["risk_score"],
                                     r["status"]))
        counts = {s: sum(1 for r in self.current_results if r["status"] == s.value)
                  for s in TrafficLight}
        self.summary_lbl.configure(
            text=f"Scan #{run_id}:  Critical {counts[TrafficLight.RED]} · Warning "
                 f"{counts[TrafficLight.YELLOW]} · Compliant {counts[TrafficLight.GREEN]} · "
                 f"Inactive {counts[TrafficLight.INACTIVE]}")
        self.set_text(self.txt_details,
                      f"Scan #{run_id} saved. Accounts checked: {len(accounts)}.\n"
                      f"Policy: max password age {policy.max_age_days} days "
                      f"(organizational rule). Select a row for findings.")
        self.set_text(self.txt_remediation, "")
        self.refresh_audit_history()
        level = "warn" if counts[TrafficLight.RED] else "ok"
        self.set_status(f"Scan #{run_id} complete: {counts[TrafficLight.RED]} critical, "
                        f"{counts[TrafficLight.YELLOW]} warning.", level)

    def show_details(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        data = next((r for r in self.current_results if r["username"] == selected[0]), None)
        if data:
            self.set_text(self.txt_details, f"[{data['status']}] {data['username']}  "
                                            f"(risk {data['risk_score']}/100)\n{data['issues']}")
            self.set_text(self.txt_remediation, data["remediation"])

    def export_csv(self):
        if not self.current_results:
            messagebox.showwarning("Nothing to export", "Run a scan first (Ctrl+R).")
            self.set_status("Export skipped: no scan in this session.", "warn")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")],
                                            title="Export scan (hash values are never exported)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["Username", "Account Type", "Hash Algorithm", "Age (Days)",
                            "Enabled", "Risk Score", "Status", "Issue Codes", "Issues",
                            "Remediation"])
                for r in self.current_results:
                    w.writerow([safe_csv_cell(v) for v in (
                        r["username"], r["type"], r["algo"], r["age"],
                        "Yes" if r["enabled"] else "No", r["risk_score"], r["status"],
                        ",".join(r["issue_codes"]), r["issues"].replace("\n", " | "),
                        r["remediation"].replace("\n", " | "))])
        except OSError as exc:
            self.error("Export failed", exc)
            return
        self.set_status(f"Report exported to {path} (no hash values included).", "ok")

    # ------------------------------------------------------------------
    # Tab 2: password strength (uses the stored policy)
    # ------------------------------------------------------------------
    def build_strength_tab(self, parent):
        self.policy_lbl = ttk.Label(parent, style="Muted.TLabel")
        self.policy_lbl.pack(anchor=tk.W, pady=(0, 8))

        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(row, text="Password to check:", style="Bold.TLabel").grid(
            row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 4))
        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(row, textvariable=self.pwd_var, show="•",
                                   font=("Consolas", 12), width=42)
        self.pwd_entry.grid(row=1, column=0, sticky=tk.W, ipady=3)
        self.pwd_entry.bind("<Return>", lambda e: self.check_strength())
        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Show", variable=self.show_pwd,
                        command=self.toggle_pwd_visibility).grid(row=1, column=1, padx=10)
        ttk.Button(row, text="🔍 Check  (Enter)", command=self.check_strength).grid(row=1, column=2)

        summary = ttk.Frame(parent)
        summary.pack(fill=tk.X, pady=(0, 8))
        self.lbl_entropy = ttk.Label(summary, text="Entropy: -", style="Bold.TLabel")
        self.lbl_entropy.pack(side=tk.LEFT, padx=(0, 20))
        self.lbl_rating = ttk.Label(summary, text="Rating: -", style="Bold.TLabel")
        self.lbl_rating.pack(side=tk.LEFT, padx=(0, 20))
        self.lbl_verdict = ttk.Label(summary, text="Verdict: -", style="Bold.TLabel")
        self.lbl_verdict.pack(side=tk.LEFT)

        self.checks_tree = self.make_table(parent, ("Check", "Kind", "Result", "Details"),
                                           (250, 90, 80, 560))
        self.checks_tree.configure(selectmode="none")
        ttk.Label(parent, style="Muted.TLabel", wraplength=1000, justify=tk.LEFT, text=(
            "Verdict = all POLICY checks pass. The NIST row is reference only: it checks the "
            "SP 800-63B-4 single-factor length floor (15), the 64-character ceiling and this "
            "app's small blocklist; it is not a compliance certification. Entropy is a "
            "charset estimate that overrates human-chosen passwords. Typed passwords are "
            "never stored, only the numeric summary.")).pack(anchor=tk.W, pady=(6, 0))
        self.refresh_policy_label()

    def refresh_policy_label(self):
        p = self.db.get_policy()
        self.policy_lbl.configure(text=(
            f"Policy loaded from database: length {p.min_length}–{p.max_length} · entropy ≥ "
            f"{p.min_entropy_bits:g} bits · composition rule "
            f"{'ON' if p.require_complexity else 'off'} · edit in Database → Policy"))

    def toggle_pwd_visibility(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "•")

    def check_strength(self):
        password = self.pwd_var.get()
        self.clear_table(self.checks_tree)
        if not password:
            self.set_status("Enter a password to check.", "warn")
            self.pwd_entry.focus_set()
            return
        policy = self.db.get_policy()
        entropy, results, compliant = sc.audit_password(password, policy)
        rating = sc.entropy_rating(entropy)
        policy_rows = [r for r in results if r["kind"] == "policy"]
        self.db.save_strength_check(entropy, rating, compliant,
                                    sum(1 for r in policy_rows if r["passed"]), len(policy_rows))
        self.refresh_strength_history()
        self.lbl_entropy.config(text=f"Entropy: {entropy:.2f} bits")
        self.lbl_rating.config(text=f"Rating: {rating}")
        c = self.colors
        if compliant:
            self.lbl_verdict.config(text="Verdict: ✅ Meets stored policy", foreground=c["ok"])
        else:
            self.lbl_verdict.config(text="Verdict: ❌ Does not meet stored policy",
                                    foreground=c["critical"])
        for r in results:
            self.checks_tree.insert("", tk.END, tags=("pass" if r["passed"] else "fail",),
                                    values=(r["name"], r["kind"].capitalize(),
                                            "PASS" if r["passed"] else "FAIL", r["message"]))
        self.set_status(f"Checked: {rating}, {'meets' if compliant else 'fails'} policy. "
                        "Only the summary was saved.", "ok" if compliant else "warn")

    # ------------------------------------------------------------------
    # Tab 3: database
    # ------------------------------------------------------------------
    def build_database_tab(self, parent):
        ttk.Label(parent, style="Muted.TLabel",
                  text=f"Runtime database: {self.db.path}").pack(anchor=tk.W, pady=(0, 6))
        tabs = ttk.Notebook(parent)
        tabs.pack(expand=True, fill=tk.BOTH)
        names = ("Accounts", "Policy", "Breach data", "Audit history", "Strength history",
                 "Maintenance")
        frames = {}
        for n in names:
            frames[n] = ttk.Frame(tabs, padding=10)
            tabs.add(frames[n], text=n)
        self.build_accounts_view(frames["Accounts"])
        self.build_policy_view(frames["Policy"])
        self.build_breach_view(frames["Breach data"])
        self.build_history_view(frames["Audit history"])
        self.build_strength_history_view(frames["Strength history"])
        self.build_maintenance_view(frames["Maintenance"])
        self.refresh_all()

    def refresh_all(self):
        self.refresh_accounts()
        self.refresh_breach_view()
        self.refresh_audit_history()
        self.refresh_strength_history()
        self.load_policy_form()

    # --- accounts ---------------------------------------------------------
    def build_accounts_view(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, pady=(0, 8))
        for text, cmd, style in (("Refresh (F5)", self.refresh_accounts, "Ghost.TButton"),
                                 ("＋ Add demo account (Ctrl+N)", self.add_demo_account, "TButton"),
                                 ("Enable / Disable", self.toggle_account_enabled, "Ghost.TButton"),
                                 ("Delete (Del)", self.delete_selected_account, "Ghost.TButton")):
            ttk.Button(bar, text=text, command=cmd, style=style).pack(side=tk.LEFT, padx=(0, 6))
        self.account_tree = self.make_table(
            parent, ("Username", "Account Type", "Age (days)", "Declared format",
                     "Stored hash (masked)", "Enabled"), (170, 150, 90, 120, 230, 80))
        self.account_tree.bind("<Delete>", lambda e: self.delete_selected_account())
        ttk.Label(parent, style="Warn.TLabel",
                  text="Demo data only. Never enter real passwords or production hashes.").pack(
            anchor=tk.W, pady=(6, 0))

    def refresh_accounts(self):
        self.clear_table(self.account_tree)
        for acc in self.db.get_accounts():
            self.account_tree.insert("", tk.END, iid=acc["username"],
                                     tags=(() if acc["enabled"] else ("inactive",)),
                                     values=(acc["username"], acc["type"].value,
                                             acc["password_age_days"], acc["hash_format"] or "auto",
                                             mask_hash(acc["hash_string"]),
                                             "Yes" if acc["enabled"] else "No"))

    def add_demo_account(self):
        dialog = self.make_dialog("Add demo account")
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        username = tk.StringVar()
        account_type = tk.StringVar(value=AccountType.STANDARD.value)
        age = tk.StringVar(value="0")
        hash_format = tk.StringVar(value="auto")
        kind = tk.StringVar(value="SHA-512-crypt (synthetic)")
        demo_hash = tk.StringVar(value=synthetic_crypt("sha512"))

        def regenerate(*_):
            if kind.get().startswith("SHA"):
                demo_hash.set(synthetic_crypt("sha512"))
            elif kind.get().startswith("bcrypt"):
                demo_hash.set(synthetic_crypt("bcrypt"))

        fields = [
            ("Username", ttk.Entry(frame, textvariable=username, width=44)),
            ("Account type", ttk.Combobox(frame, textvariable=account_type, state="readonly",
                                          values=[t.value for t in AccountType], width=41)),
            ("Password age (days)", ttk.Spinbox(frame, textvariable=age, from_=0, to=9999,
                                                width=42)),
            ("Hash generator", ttk.Combobox(frame, textvariable=kind, state="readonly", width=41,
                                            values=["SHA-512-crypt (synthetic)",
                                                    "bcrypt (synthetic)", "Custom value"])),
            ("Simulated hash", ttk.Entry(frame, textvariable=demo_hash, width=44)),
            ("Declared format", ttk.Combobox(frame, textvariable=hash_format, state="readonly",
                                             values=["auto", "NTLM", "MD5"], width=41)),
        ]
        for i, (label, widget) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=4)
            widget.grid(row=i, column=1, sticky=tk.W, padx=8, pady=4)
        fields[3][1].bind("<<ComboboxSelected>>", regenerate)
        ttk.Label(frame, style="Warn.TLabel", wraplength=420, text=(
            "Educational data only. 'Declared format' tells the auditor how to read a "
            "32-hex value (NTLM for AD exports); leave 'auto' otherwise.")).grid(
            row=len(fields), column=0, columnspan=2, pady=8, sticky=tk.W)

        def submit(event=None):
            try:
                if not demo_hash.get().strip():
                    raise ValueError("Enter a simulated hash")
                fmt = "" if hash_format.get() == "auto" else hash_format.get()
                self.db.add_account(username.get(), account_type.get(), age.get(),
                                    demo_hash.get(), hash_format=fmt)
            except sqlite3.IntegrityError:
                self.error("Cannot add account", f"'{username.get().strip()}' already exists "
                           "or a value is invalid.", parent=dialog)
                return
            except ValueError as exc:
                self.error("Cannot add account", exc, parent=dialog)
                return
            self.refresh_accounts()
            self.set_status(f"Account '{username.get().strip()}' added. Run a scan to audit it.",
                            "ok")
            dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(fields) + 1, column=1, sticky=tk.E)
        ttk.Button(buttons, text="Cancel (Esc)", style="Ghost.TButton",
                   command=dialog.destroy).pack(side=tk.LEFT, padx=6)
        ttk.Button(buttons, text="Save (Enter)", command=submit).pack(side=tk.LEFT)
        dialog.bind("<Return>", submit)
        fields[0][1].focus_set()

    def _selected_account(self):
        selection = self.account_tree.selection()
        if not selection:
            self.set_status("Select an account first.", "warn")
            return None
        return selection[0]

    def toggle_account_enabled(self):
        name = self._selected_account()
        if not name:
            return
        enabled = self.account_tree.set(name, "Enabled") == "Yes"
        self.db.set_account_enabled(name, not enabled)
        self.refresh_accounts()
        self.set_status(f"'{name}' is now {'disabled' if enabled else 'enabled'}.", "ok")

    def delete_selected_account(self):
        name = self._selected_account()
        if name and messagebox.askyesno("Confirm deletion", f"Delete demo account '{name}'?\n"
                                        "Saved scan history is kept."):
            self.db.delete_account(name)
            self.refresh_accounts()
            self.set_status(f"Account '{name}' deleted.", "ok")

    # --- policy -----------------------------------------------------------
    def build_policy_view(self, parent):
        ttk.Label(parent, style="Bold.TLabel", text=(
            "One policy drives both the account audit and the password checker.")).pack(
            anchor=tk.W, pady=(0, 10))
        form = ttk.Frame(parent)
        form.pack(anchor=tk.W)
        self.policy_vars = {k: tk.StringVar() for k in (
            "min_length", "max_length", "min_entropy_bits", "max_age_days", "lockout_threshold")}
        self.policy_complexity = tk.BooleanVar()
        labels = [("min_length", "Minimum length"), ("max_length", "Maximum length"),
                  ("min_entropy_bits", "Minimum entropy (bits)"),
                  ("max_age_days", "Maximum password age (days)"),
                  ("lockout_threshold", "Lockout threshold (attempts)")]
        for i, (key, label) in enumerate(labels):
            ttk.Label(form, text=label).grid(row=i, column=0, sticky=tk.W, pady=4)
            ttk.Spinbox(form, textvariable=self.policy_vars[key], from_=0, to=9999,
                        width=10).grid(row=i, column=1, sticky=tk.W, padx=10)
        ttk.Checkbutton(form, text="Require composition (3 of 4 character classes)",
                        variable=self.policy_complexity).grid(row=len(labels), column=0,
                                                              columnspan=2, sticky=tk.W, pady=6)
        ttk.Button(form, text="Save policy", command=self.save_policy).grid(
            row=len(labels) + 1, column=0, sticky=tk.W, pady=8)
        self.policy_notes = ttk.Label(parent, style="Muted.TLabel", justify=tk.LEFT,
                                      wraplength=900)
        self.policy_notes.pack(anchor=tk.W, pady=(8, 0))

    def load_policy_form(self):
        p = self.db.get_policy()
        for key, var in self.policy_vars.items():
            var.set(f"{getattr(p, key):g}" if key == "min_entropy_bits" else getattr(p, key))
        self.policy_complexity.set(p.require_complexity)
        self.update_policy_notes(p)

    def update_policy_notes(self, p):
        notes = []
        if p.min_length < sc.NIST_SINGLE_FACTOR_MIN:
            notes.append(f"• Minimum length {p.min_length} is below NIST SP 800-63B-4's 15 for "
                         "single-factor passwords (8 is allowed only with MFA).")
        if p.require_complexity:
            notes.append("• Composition rules: NIST SP 800-63B-4 says verifiers SHALL NOT "
                         "impose them.")
        notes.append(f"• Maximum age {p.max_age_days} days is an organizational rule; NIST "
                     "SP 800-63B-4 requires a change only on evidence of compromise.")
        notes.append("• Lockout threshold is stored for reference; this offline tool does "
                     "not evaluate authentication attempts.")
        self.policy_notes.configure(text="Standards notes:\n" + "\n".join(notes))

    def save_policy(self):
        try:
            v = {k: var.get().strip() for k, var in self.policy_vars.items()}
            policy = SystemPolicy(min_length=int(v["min_length"]),
                                  require_complexity=self.policy_complexity.get(),
                                  max_age_days=int(v["max_age_days"]),
                                  lockout_threshold=int(v["lockout_threshold"]),
                                  max_length=int(v["max_length"]),
                                  min_entropy_bits=float(v["min_entropy_bits"]))
            self.db.update_policy(policy)
        except ValueError as exc:
            self.error("Policy not saved", exc)
            return
        self.update_policy_notes(policy)
        self.refresh_policy_label()
        self.set_status("Policy saved. Both the audit and the checker now use it.", "ok")

    # --- breach data --------------------------------------------------------
    def build_breach_view(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(bar, text="Import breach file…", command=self.import_breaches).pack(side=tk.LEFT)
        ttk.Label(bar, style="Muted.TLabel", text=(
            "One 32-hex value per line, or HIBP 'HASH:COUNT'. Every import needs an "
            "algorithm and a documented source.")).pack(side=tk.LEFT, padx=12)
        self.breach_tree = self.make_table(parent, ("Algorithm", "Source (provenance)", "Entries",
                                                    "First added"), (90, 560, 80, 200))
        ttk.Label(parent, style="Muted.TLabel", wraplength=1000, justify=tk.LEFT, text=(
            "Matching is algorithm-aware: an NTLM value is only compared with NTLM entries. "
            "Salted formats (bcrypt, SHA-crypt…) cannot be matched against a breach corpus by "
            "string comparison, so they are only flagged on an exact leaked record.")).pack(
            anchor=tk.W, pady=(6, 0))

    def refresh_breach_view(self):
        self.clear_table(self.breach_tree)
        for row in self.db.get_breach_summary():
            self.breach_tree.insert("", tk.END, values=(row["algorithm"], row["source"],
                                                        row["entries"], row["first_added"]))

    def import_breaches(self):
        path = filedialog.askopenfilename(title="Breach list (one hash per line)",
                                          filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        algorithm = simpledialog.askstring("Algorithm", "Algorithm of these hashes (NTLM or MD5):",
                                           initialvalue="NTLM", parent=self.root)
        if not algorithm:
            return
        source = simpledialog.askstring("Source", "Where does this list come from? "
                                        "(name, date, licence)", parent=self.root)
        if not source:
            self.set_status("Import cancelled: a source is required.", "warn")
            return
        try:
            added, dup, rejected = self.db.import_breach_file(path, algorithm, source)
        except (ValueError, OSError) as exc:
            self.error("Import failed", exc)
            return
        self.refresh_breach_view()
        self.set_status(f"Imported {added} entries ({dup} duplicates, {rejected} invalid lines).",
                        "ok" if added else "warn")

    # --- audit history, comparison, trend ------------------------------------
    def build_history_view(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, pady=(0, 8))
        for text, cmd, style in (("Open run (Enter)", self.show_saved_audit, "TButton"),
                                 ("Compare with previous", self.compare_selected_run, "TButton"),
                                 ("Export run…", self.export_selected_run, "Ghost.TButton"),
                                 ("Refresh", self.refresh_audit_history, "Ghost.TButton")):
            ttk.Button(bar, text=text, command=cmd, style=style).pack(side=tk.LEFT, padx=(0, 6))
        self.history_tree = self.make_table(
            parent, ("Run", "Date", "Checked", "Critical", "Warning", "Compliant", "Inactive",
                     "Avg risk"), (55, 210, 75, 75, 75, 85, 75, 80), height=7)
        self.history_tree.bind("<Double-1>", self.show_saved_audit)
        self.history_tree.bind("<Return>", self.show_saved_audit)
        ttk.Label(parent, style="Bold.TLabel",
                  text="Risk trend (oldest → newest, last 20 runs)").pack(anchor=tk.W, pady=(10, 2))
        self.trend_canvas = tk.Canvas(parent, height=190, highlightthickness=0)
        self.trend_canvas.pack(fill=tk.X)
        self.trend_canvas.bind("<Configure>", lambda e: self.draw_trend())
        self.canvases.append(self.trend_canvas)

    def refresh_audit_history(self):
        if not hasattr(self, "history_tree"):
            return
        self.clear_table(self.history_tree)
        for run in self.db.get_audit_runs():
            avg = "-" if run["avg_risk"] is None else f"{run['avg_risk']:.1f}"
            self.history_tree.insert("", tk.END, iid=str(run["id"]), values=(
                run["id"], run["created_at"], run["accounts_checked"], run["critical_count"],
                run["warning_count"], run["compliant_count"], run["inactive_count"], avg))
        self.draw_trend()

    def draw_trend(self):
        canvas = getattr(self, "trend_canvas", None)
        if canvas is None:
            return
        c = self.colors
        canvas.delete("all")
        canvas.configure(bg=c["surface"])
        w, h = max(canvas.winfo_width(), 400), int(canvas["height"])
        left, right, top, bottom = 50, 20, 26, 28
        runs = self.db.get_trend(20)
        if not runs:
            canvas.create_text(w / 2, h / 2, text="No scans yet: run one to start a trend.",
                               fill=c["muted"], font=("Segoe UI", 10))
            return
        for v in (0, 25, 50, 75, 100):
            y = h - bottom - (h - top - bottom) * v / 100
            canvas.create_line(left, y, w - right, y, fill=c["grid"])
            canvas.create_text(left - 8, y, text=str(v), anchor=tk.E, fill=c["muted"],
                               font=("Segoe UI", 8))
        n = len(runs)
        step = (w - left - right) / max(n, 1)
        avg_pts = []
        for i, run in enumerate(runs):
            x = left + step * (i + 0.5)
            share = 100 * run["critical_count"] / run["accounts_checked"] if run["accounts_checked"] else 0
            y_share = h - bottom - (h - top - bottom) * share / 100
            canvas.create_rectangle(x - step * 0.3, y_share, x + step * 0.3, h - bottom,
                                    fill=c["bar"], outline="")
            canvas.create_text(x, h - bottom + 12, text=f"#{run['id']}", fill=c["muted"],
                               font=("Segoe UI", 8))
            if run["avg_risk"] is not None:
                avg_pts.append((x, h - bottom - (h - top - bottom) * run["avg_risk"] / 100))
        if len(avg_pts) > 1:
            canvas.create_line(*[v for p in avg_pts for v in p], fill=c["accent"], width=2)
        for x, y in avg_pts:
            canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=c["accent"], outline=c["surface"])
        canvas.create_oval(left, 6, left + 8, 14, fill=c["accent"], outline="")
        canvas.create_text(left + 14, 10, anchor=tk.W, fill=c["fg"], font=("Segoe UI", 9),
                           text="Line: average risk of active accounts (0–100)")
        canvas.create_rectangle(left + 330, 5, left + 344, 15, fill=c["bar"], outline="")
        canvas.create_text(left + 350, 10, anchor=tk.W, fill=c["fg"], font=("Segoe UI", 9),
                           text="Bars: % of accounts critical")

    def _selected_run(self):
        selection = self.history_tree.selection()
        if not selection:
            self.set_status("Select a run in the history table first.", "warn")
            return None
        return int(selection[0])

    def show_saved_audit(self, event=None):
        run_id = self._selected_run()
        if run_id is None:
            return
        saved = self.db.get_audit_results(run_id)
        window = self.make_dialog(f"Saved audit #{run_id}", "980x560")
        frame = ttk.Frame(window, padding=12)
        frame.pack(expand=True, fill=tk.BOTH)
        tree = self.make_table(frame, ("Username", "Algorithm", "Age", "Risk", "Status"),
                               (170, 320, 70, 70, 140))
        _, details = self.make_text(frame, height=9)
        details.master.pack(fill=tk.X, pady=(10, 0))
        self.apply_theme(self.theme_name)
        for index, r in enumerate(saved):
            tree.insert("", tk.END, iid=str(index), tags=_tags(STATUS_TAGS.get(r["status"])),
                        values=(r["username"], r["hash_algorithm"], r["age_days"],
                                r["risk_score"], r["status"]))

        def select(event=None):
            sel = tree.selection()
            if sel:
                r = saved[int(sel[0])]
                body = f"User: {r['username']}\n{r['issues']}"
                if r["remediation"]:
                    body += f"\n\nRemediation:\n{r['remediation']}"
                self.set_text(details, body)

        tree.bind("<<TreeviewSelect>>", select)
        if saved:
            tree.selection_set("0")
            tree.focus("0")
        tree.focus_set()

    def compare_selected_run(self):
        run_id = self._selected_run()
        if run_id is None:
            return
        previous_id, rows = self.db.compare_runs(run_id)
        if previous_id is None:
            self.set_status(f"Run #{run_id} is the first run; nothing to compare.", "warn")
            return
        window = self.make_dialog(f"Run #{run_id} vs run #{previous_id}", "860x420")
        frame = ttk.Frame(window, padding=12)
        frame.pack(expand=True, fill=tk.BOTH)
        tree = self.make_table(frame, ("Username", f"Risk #{previous_id}", f"Risk #{run_id}",
                                       "Δ", "Change", "Status now"), (170, 90, 90, 60, 130, 140))
        self.apply_theme(self.theme_name)
        tag_for = {"Improved": "ok", "Worse": "critical", "New account": "warning",
                   "Removed": "inactive"}
        for r in rows:
            fmt = lambda v: "-" if v is None else v
            delta = "-" if r["delta"] is None else f"{r['delta']:+d}"
            tree.insert("", tk.END, tags=_tags(tag_for.get(r["change"])), values=(
                r["username"], fmt(r["previous_risk"]), fmt(r["current_risk"]), delta,
                r["change"], r["current_status"]))
        worse = sum(1 for r in rows if r["change"] == "Worse")
        better = sum(1 for r in rows if r["change"] == "Improved")
        ttk.Label(frame, style="Bold.TLabel",
                  text=f"{better} improved · {worse} worse · "
                       f"{sum(1 for r in rows if r['change'] == 'New account')} new · "
                       f"{sum(1 for r in rows if r['change'] == 'Removed')} removed").pack(
            anchor=tk.W, pady=(8, 0))

    def export_selected_run(self):
        run_id = self._selected_run()
        if run_id is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            initialfile=f"hashy-run-{run_id}.csv",
                                            filetypes=[("CSV files", "*.csv")])
        if path:
            try:
                n = self.db.export_run_csv(run_id, path)
            except OSError as exc:
                self.error("Export failed", exc)
                return
            self.set_status(f"Run #{run_id} exported ({n} rows, no hash values).", "ok")

    # --- strength history ---------------------------------------------------
    def build_strength_history_view(self, parent):
        ttk.Label(parent, style="Muted.TLabel", text=(
            "Only numeric results are saved, never the passwords typed in the checker.")).pack(
            anchor=tk.W, pady=(0, 8))
        self.strength_history_tree = self.make_table(
            parent, ("ID", "Date", "Entropy", "Rating", "Meets policy", "Policy checks passed"),
            (60, 230, 90, 120, 110, 160))

    def refresh_strength_history(self):
        if not hasattr(self, "strength_history_tree"):
            return
        self.clear_table(self.strength_history_tree)
        for item in self.db.get_strength_checks():
            self.strength_history_tree.insert("", tk.END, values=(
                item["id"], item["created_at"], f"{item['entropy']:.2f}", item["rating"],
                "Yes" if item["compliant"] else "No",
                f"{item['checks_passed']}/{item['checks_total']}"))

    # --- maintenance --------------------------------------------------------
    def build_maintenance_view(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, pady=(0, 8))
        for text, cmd, style in (("Back up now (Ctrl+B)", self.backup_db, "TButton"),
                                 ("Restore from backup…", self.restore_db, "Ghost.TButton"),
                                 ("Integrity check", self.show_integrity, "Ghost.TButton"),
                                 ("Reset to sample data…", self.reset_sample, "Ghost.TButton")):
            ttk.Button(bar, text=text, command=cmd, style=style).pack(side=tk.LEFT, padx=(0, 6))
        frame, self.maint_text = self.make_text(parent, height=14)
        frame.pack(expand=True, fill=tk.BOTH)
        self.set_text(self.maint_text, (
            f"Runtime DB: {self.db.path}\nBackups:    {self.db.backup_dir}\n\n"
            "Backups use SQLite's online backup API. Restore verifies integrity first and "
            "backs up the current database before replacing it."))

    def backup_db(self):
        try:
            path = self.db.backup()
        except (sqlite3.Error, OSError) as exc:
            self.error("Backup failed", exc)
            return
        self.set_status(f"Backup written: {path.name}", "ok")
        self.show_integrity()

    def restore_db(self):
        path = filedialog.askopenfilename(initialdir=str(self.db.backup_dir),
                                          title="Choose a HASHY backup",
                                          filetypes=[("SQLite DB", "*.db")])
        if not path or not messagebox.askyesno(
                "Restore backup", "Replace the current database with this backup?\n"
                "The current database is backed up first."):
            return
        try:
            safety = self.db.restore(path)
        except (sqlite3.Error, ValueError, OSError) as exc:
            self.error("Restore failed", exc)
            return
        self.current_results = []
        self.clear_table(self.tree)
        self.refresh_all()
        self.refresh_policy_label()
        self.set_status(f"Restored. Previous database saved as {safety.name}.", "ok")

    def show_integrity(self):
        r = self.db.integrity_report()
        counts = "\n".join(f"  {k:<16} {v}" for k, v in r["row_counts"].items())
        self.set_text(self.maint_text, (
            f"Runtime DB:          {self.db.path}\n"
            f"Schema version:      {r['schema_version']}\n"
            f"PRAGMA integrity:    {r['integrity_check']}\n"
            f"FK violations:       {r['foreign_key_violations']}\n"
            f"Backups on disk:     {r['backups']} (latest: {r['latest_backup'] or 'none'})\n\n"
            f"Row counts:\n{counts}"))
        ok = r["integrity_check"] == "ok" and r["foreign_key_violations"] == 0
        self.set_status("Integrity check passed." if ok else "Integrity problems found!",
                        "ok" if ok else "error")

    def reset_sample(self):
        if not messagebox.askyesno("Reset to sample data", (
                "Replace accounts, policy and breach data with the synthetic sample?\n"
                "Scan and strength history are kept. A backup is made first.")):
            return
        backup = self.db.reset_to_sample()
        self.refresh_all()
        self.refresh_policy_label()
        self.set_status(f"Sample data restored (backup: {backup.name}).", "ok")

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------
    def show_shortcuts(self):
        dialog = self.make_dialog("Keyboard shortcuts")
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        for i, (keys, action) in enumerate(SHORTCUTS):
            ttk.Label(frame, text=keys, style="Bold.TLabel").grid(row=i, column=0, sticky=tk.W,
                                                                  padx=(0, 20), pady=2)
            ttk.Label(frame, text=action).grid(row=i, column=1, sticky=tk.W, pady=2)
        ttk.Button(frame, text="Close (Esc)", command=dialog.destroy).grid(
            row=len(SHORTCUTS), column=1, sticky=tk.E, pady=(10, 0))

    def show_about(self):
        messagebox.showinfo("Scope & limitations", (
            "HASHY is an educational auditor for SYNTHETIC data.\n\n"
            "• No connection to Active Directory, /etc/shadow or Have I Been Pwned; all "
            "sources are simulated or imported files.\n"
            "• The NIST row is a subset of SP 800-63B-4, not a compliance certification.\n"
            "• Entropy is a charset estimate and overrates human-chosen passwords.\n"
            "• Salted hashes cannot reveal reuse or breach status by string comparison.\n"
            "• The SQLite database is not encrypted: never store real hashes in it."))


def main():
    root = tk.Tk()
    ModernAuditorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
