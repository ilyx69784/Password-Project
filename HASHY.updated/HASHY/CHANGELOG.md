# Changelog

## 2.0.0 (2026-11-12): HASHY improvement plan implemented

### P0 Fix first
- Scrollbars use `yscrollcommand` in every table and text pane; GUI start verified.
- One `SystemPolicy` in SQLite drives the audit and the strength checker
  (new columns `max_length`, `min_entropy_bits`; policy editor in the GUI).
- NIST check relabelled as an SP 800-63B-4 subset (15-char single-factor floor,
  64 ceiling, blocklist) and excluded from the verdict; disabled accounts -> Inactive.

### P1 Strengthen
- 32-hex values are ambiguous (NTLM/MD5) unless `hash_format` is declared.
- Reuse is only claimed for unsalted hashes; identical salted strings are reported
  as copied records. Structural validation for bcrypt, SHA-256/512-crypt,
  MD5-crypt, yescrypt, Argon2; malformed values are never "compliant".
- `breach_entries` with algorithm + source; reproducible sample; HIBP-format import.
- Hashes masked in the GUI and never exported; CSV formula-injection protection.

### P2 Verify
- 47 unit/integration tests (auditor, strength checker, migrations, backups, exports).
- Runtime DB moved to `data/` and created from `sample_data.py`; migrations with
  automatic pre-migration backup; backup/restore/integrity check/reset in the GUI.
- Logo-coloured dark/light themes (saved), window icon, keyboard shortcuts, status bar.

### P3 Expand
- Run comparison (per-account risk delta) and risk trend chart.
- Remediation guidance per issue code in the GUI, CSV and database.
- README.md, README_RU.md, release checklist, run scripts.
