import csv, shutil
from collections import defaultdict
from datetime import date
from pathlib import Path

RAW, OUT = Path("raw_sap"), Path("data_sap")


def read(name):
    with open(RAW / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def sap_date(s):  # SAP dates are YYYYMMDD
    return date(int(s[:4]), int(s[4:6]), int(s[6:8]))


def write(name, header, rows):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main(today=None):
    today = today or date.today()
    tcodes, auth = defaultdict(set), defaultdict(set)
    for r in read("AGR_TCODES.csv"):
        tcodes[r["AGR_NAME"]].add(r["TCODE"])
    for r in read("AGR_1251.csv"):
        key = (r["AGR_NAME"], r["OBJECT"], r["FIELD"])
        auth[key].add(r["LOW"])
        if r["HIGH"]:  # value ranges are not expanded: treated as "all" (conservative)
            auth[key].add("*")
    pmap = read("permission_map.csv")

    role_perms = set()  # (role, permission, org_unit)
    for role in set(tcodes) | {k[0] for k in auth}:
        for m in pmap:
            allowed = set(m["allowed_values"].split("|"))
            values = auth.get((role, m["object"], m["field"]), set())
            if m["tcode"] in tcodes[role] and (values & allowed or "*" in values):
                org_field = m.get("org_field")
                orgs = auth.get((role, m["object"], org_field), set()) if org_field else set()
                for org in (orgs or {"*"}):  # no org restriction = all units
                    role_perms.add((role, m["permission"], org))

    dept = {r["UNAME"]: r["DEPARTMENT"] for r in read("users.csv")}
    user_roles = []
    for r in read("AGR_USERS.csv"):
        if sap_date(r["FROM_DAT"]) <= today <= sap_date(r["TO_DAT"]):
            user_roles.append((r["UNAME"], dept.get(r["UNAME"], "Unknown"), r["AGR_NAME"]))

    OUT.mkdir(exist_ok=True)
    write("user_roles.csv", ["user_id", "department", "role"], sorted(user_roles))
    write("role_permissions.csv", ["role", "permission", "org_unit"], sorted(role_perms))
    shutil.copy(RAW / "sod_rules.csv", OUT / "sod_rules.csv")
    print(f"{len(user_roles)} active assignments, {len(role_perms)} role-permission rows written to {OUT}/")


if __name__ == "__main__":
    main()