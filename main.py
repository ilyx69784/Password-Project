"""
main.py

Driver for the Password Security & Compliance Auditor.

Usage:
    python3 main.py                       # run with defaults, print + save report
    python3 main.py --n 100 --seed 7       # different synthetic dataset size/seed
    python3 main.py --corpus wordlist.txt  # use a real breach/dictionary corpus
    python3 main.py --out audit_report.md  # custom output path

Swap the OrgPolicyConfig block below for the actual policy under audit,
or wire in argparse flags if you need it configurable per-run.
"""

from __future__ import annotations
import argparse
import sys

from synth_data import generate_dataset
from nist_checker import OrgPolicyConfig
from report import audit_organization, render_markdown


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Simulated organizational password audit.")
    p.add_argument("--n", type=int, default=40, help="number of synthetic accounts")
    p.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    p.add_argument("--corpus", type=str, default=None,
                    help="path to a newline-delimited breach/dictionary wordlist "
                         "(defaults to the small embedded demo list)")
    p.add_argument("--org-name", type=str, default="Sample Org")
    p.add_argument("--out", type=str, default="audit_report.md")
    return p


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    accounts = generate_dataset(n=args.n, seed=args.seed)

    # This is the policy under audit. Replace with the org's real config
    # (or load it from a JSON/YAML file) for a non-simulated run.
    policy = OrgPolicyConfig(
        min_length=8, max_length=16,
        requires_uppercase=True, requires_lowercase=True,
        requires_digit=True, requires_symbol=True,
        forces_periodic_rotation=True, rotation_days=90,
        allows_password_hints=True,
        uses_knowledge_based_auth=False,
        checks_against_breach_corpus=False,
        allows_paste_into_password_field=True,
        truncates_at_char_limit=True,
        blocks_unicode_and_spaces=False,
    )

    result = audit_organization(accounts, policy, corpus_path=args.corpus)
    report_text = render_markdown(result, org_name=args.org_name)

    with open(args.out, "w") as f:
        f.write(report_text)

    print(report_text)
    print(f"\n\n[report written to {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
