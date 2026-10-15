import csv, json
from collections import defaultdict
from pathlib import Path
from datetime import date
import sys

DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output")

def read_csv(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def build_role_perms(rows):
    rp = defaultdict(set)
    for r in rows:
        rp[r["role"]].add(r["permission"])
    return rp

def build_users(rows, role_perms):
    users = {}
    for r in rows:
        u = users.setdefault(r["user_id"], {"department": r["department"], "roles": set()})
        u["roles"].add(r["role"])
    for u in users.values():
        u["permissions"] = set().union(*(role_perms.get(r, set()) for r in u["roles"]))
    return users

def analyze(users, rules, role_perms):
    findings = []
    for uid, u in sorted(users.items()):
        for rule in rules:
            required = set(rule["required_permissions"].split("|"))
            if required <= u["permissions"]:  # all required permissions present
                evidence = {
                    p: sorted(r for r in u["roles"] if p in role_perms[r])
                    for p in sorted(required)
                }
                findings.append({
                    "user_id": uid,
                    "department": u["department"],
                    "rule_id": rule["rule_id"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "conflicting_permissions": sorted(required),
                    "granted_by_roles": evidence,
                })
    return findings
SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 3, "Low": 1}  # illustrative weights
SEVERITIES = ["Low", "Medium", "High", "Critical"]
def build_role_orgs(rows):
    orgs = defaultdict(set)
    for r in rows:
        orgs[(r["role"], r["permission"])].add(r.get("org_unit") or "*")
    return orgs

def org_overlap(orgsets):
    # "*" matches any org; the remaining sets must share at least one org
    concrete = [s for s in orgsets if "*" not in s]
    if not concrete:
        return True
    return bool(set.intersection(*concrete))

def apply_org_conditions(findings, rules, role_orgs):
    rule_by_id = {r["rule_id"]: r for r in rules}
    kept, suppressed = [], []
    for f in findings:
        if rule_by_id[f["rule_id"]].get("same_org", "N").upper() != "Y":
            kept.append(f)
            continue
        orgsets = []
        for perm, roles in f["granted_by_roles"].items():
            s = set()
            for role in roles:
                s |= role_orgs.get((role, perm), {"*"})
            orgsets.append(s)
        (kept if org_overlap(orgsets) else suppressed).append(f)
    return kept, suppressed
def load_exceptions(rows):
    exceptions = {}
    for r in rows:
        if r["residual_severity"] not in SEVERITIES:
            raise ValueError(f"Invalid residual_severity for {r['user_id']}/{r['rule_id']}")
        exceptions[(r["user_id"], r["rule_id"])] = r
    return exceptions

def apply_exceptions(findings, exceptions, today=None):
    today = today or date.today()
    for f in findings:
        f["inherent_severity"] = f["severity"]
        f["status"], f["control"] = "Open", ""
        e = exceptions.get((f["user_id"], f["rule_id"]))
        if not e:
            continue
        f["control"] = e["control_id"]
        if date.fromisoformat(e["expiry_date"]) >= today:
            f["status"] = "Mitigated"
            # a control can lower severity, never raise it
            lowest = min(SEVERITIES.index(e["residual_severity"]),
                         SEVERITIES.index(f["inherent_severity"]))
            f["severity"] = SEVERITIES[lowest]
        else:
            f["status"] = "Exception expired"
    return findings
def summarize(users, findings):
    by_severity, by_rule, by_status, user_scores = (
        defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(int)
    )
    for f in findings:
        by_severity[f["severity"]] += 1
        by_rule[f["rule_id"]] += 1
        by_status[f.get("status", "Open")] += 1
        user_scores[f["user_id"]] += SEVERITY_WEIGHT.get(f["severity"], 0)

    ranked = sorted(user_scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "users_analyzed": len(users),
        "users_with_findings": len(user_scores),
        "total_findings": len(findings),
        "by_severity": dict(by_severity),
        "by_status": dict(by_status),
        "by_rule": dict(sorted(by_rule.items())),
        "riskiest_users": [{"user_id": u, "risk_score": s} for u, s in ranked],
    }
def main():
    role_perms = build_role_perms(read_csv("role_permissions.csv"))
    users = build_users(read_csv("user_roles.csv"), role_perms)
    rules = read_csv("sod_rules.csv")
    findings = analyze(users, rules, role_perms)
    role_orgs = build_role_orgs(read_csv("role_permissions.csv"))
    findings, suppressed = apply_org_conditions(findings, rules, role_orgs)
    exc_file = DATA / "exceptions.csv"
    exceptions = load_exceptions(read_csv("exceptions.csv")) if exc_file.exists() else {}
    findings = apply_exceptions(findings, exceptions)

    OUT.mkdir(exist_ok=True)
    with open(OUT / "findings.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    with open(OUT / "findings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["user_id", "department", "rule_id", "inherent_severity",
                    "effective_severity", "status", "control", "conflict", "roles_involved"])
        for x in findings:
            roles = sorted({r for rs in x["granted_by_roles"].values() for r in rs})
            w.writerow([x["user_id"], x["department"], x["rule_id"], x["inherent_severity"],
                        x["severity"], x["status"], x["control"],
                        " + ".join(x["conflicting_permissions"]), ", ".join(roles)])

    summary = summarize(users, findings)
    with open(OUT / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"{summary['users_analyzed']} users analyzed, "
          f"{summary['users_with_findings']} with findings, "
          f"{summary['total_findings']} findings total")
    print("\nBy severity:", summary["by_severity"])
    print("By status:  ", summary["by_status"])
    print("By rule:    ", summary["by_rule"])
    print("\nRiskiest users:")
    for r in summary["riskiest_users"]:
        print(f"  {r['user_id']}  score {r['risk_score']}")
    expired = [x for x in findings if x["status"] == "Exception expired"]
    for x in expired:
        print(f"\n! Expired exception: {x['user_id']} {x['rule_id']} (control {x['control']})")
    print(f"\nSuppressed findings: {len(suppressed)}")
    for x in suppressed:
        print(f"\nSuppressed (no org overlap): {x['user_id']} {x['rule_id']}")

    with open(OUT / "suppressed.json", "w", encoding="utf-8") as f:
        json.dump(suppressed, f, indent=2)
if __name__ == "__main__":
    main()