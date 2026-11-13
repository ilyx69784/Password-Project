# Release checklist

Run from the project folder. Every box must be ticked before a ZIP is shared.

- [ ] Python 3.10+ (`py --version`); Tkinter available (`py -c "import tkinter"`).
- [ ] `py -m unittest -v`: all 47 tests pass.
- [ ] `py main.py` starts; Run Scan works; both themes readable; scrollbars move.
- [ ] Ctrl+R, Ctrl+E, Ctrl+B, Ctrl+T, F1 and Esc behave as documented.
- [ ] `py view_database.py` shows schema v2 and `integrity: ok`.
- [ ] No runtime data in the package: `data/`, `*.db`, `__pycache__/` excluded.
- [ ] No real credentials: only synthetic values in `sample_data.py`; no imported real hash dumps in the package.
- [ ] README.md / README_RU.md test count and screenshots match this build.
- [ ] CHANGELOG.md updated; version tag created.
- [ ] Only the canonical `HASHY` build is in the ZIP (alternate `/password` folder archived).
