"""Builds the Lab 5 summary from semgrep JSON: python semgrep_report.py semgrep-results.json [more.json ...] > semgrep_report.md"""
import json
import sys
from collections import Counter

FOCUS = {"useless-inner-function": "Move view functions to module level and register them explicitly.",
         "django-no-csrf-token": "Django rule on a Flask/Jinja template: CSRF is enforced by Flask-WTF (hidden csrf_token field). False positive.",
         "sql": "Use parameterised queries only.", "secret": "Move secrets to environment variables or a secret store."}


def main(paths):
    results, errors, rules = [], [], 0
    for p in paths:
        d = json.load(open(p))
        results += d["results"]
        errors += d.get("errors", [])
        rules = max(rules, len(d.get("paths", {}).get("scanned", [])))
    sev = Counter(r["extra"]["severity"] for r in results)
    files = Counter(r["path"] for r in results)
    ids = Counter(r["check_id"].split(".")[-1] for r in results)
    print("# Semgrep SAST report\n")
    print(f"- Input files: {', '.join(paths)}\n- Total findings: {len(results)}\n- Parse errors (non-code): {len(errors)}")
    print("\n## Findings by severity\n| Severity | Count |\n|---|---|")
    for k in ("ERROR", "WARNING", "INFO"):
        print(f"| {k} | {sev.get(k, 0)} |")
    print("\n## Affected files\n| File | Findings |\n|---|---|")
    for f, n in files.most_common():
        print(f"| {f} | {n} |")
    if not files:
        print("| none | 0 |")
    print("\n## Most important rule IDs\n| Rule | Count | Remediation focus |\n|---|---|---|")
    for rid, n in ids.most_common(10):
        print(f"| {rid} | {n} | {FOCUS.get(rid, 'Review manually.')} |")
    if not ids:
        print("| none | 0 | |")
    print("\n## Detail\n| Severity | Rule | Location | Message |\n|---|---|---|---|")
    for r in results:
        msg = r["extra"]["message"].replace("\n", " ")[:140]
        print(f"| {r['extra']['severity']} | {r['check_id'].split('.')[-1]} | {r['path']}:{r['start']['line']} | {msg} |")


if __name__ == "__main__":
    main(sys.argv[1:])
