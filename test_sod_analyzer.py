import unittest
from datetime import date
from sod_analyzer import (
    build_role_perms, build_users, analyze, summarize,
    load_exceptions, apply_exceptions,
    build_role_orgs, org_overlap, apply_org_conditions,
)

RULES = [{
    "rule_id": "SOD-01",
    "required_permissions": "VENDOR_MAINTAIN|PAYMENT_EXECUTE",
    "severity": "Critical",
    "description": "test rule",
}]

ROLE_ROWS = [
    {"role": "VENDOR_ADMIN", "permission": "VENDOR_MAINTAIN"},
    {"role": "PAYER", "permission": "PAYMENT_EXECUTE"},
]


def run(user_rows, role_rows=ROLE_ROWS, rules=RULES):
    rp = build_role_perms(role_rows)
    users = build_users(user_rows, rp)
    return users, analyze(users, rules, rp)


def row(uid, role):
    return {"user_id": uid, "department": "Test", "role": role}


class TestSoDAnalyzer(unittest.TestCase):

    # ---- Stage 4: core engine ----

    def test_conflict_detected(self):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule_id"], "SOD-01")

    def test_single_half_not_flagged(self):
        _, f = run([row("U1", "VENDOR_ADMIN")])
        self.assertEqual(f, [])

    def test_duplicate_rows_do_not_duplicate_findings(self):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")])
        self.assertEqual(len(f), 1)

    def test_unknown_role_is_ignored_without_crash(self):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "GHOST_ROLE")])
        self.assertEqual(f, [])

    def test_empty_assignments(self):
        users, f = run([])
        self.assertEqual(users, {})
        self.assertEqual(f, [])

    def test_evidence_names_the_granting_roles(self):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")])
        self.assertEqual(f[0]["granted_by_roles"], {
            "PAYMENT_EXECUTE": ["PAYER"],
            "VENDOR_MAINTAIN": ["VENDOR_ADMIN"],
        })

    def test_single_role_holding_both_permissions_flagged_once(self):
        roles = [
            {"role": "SUPER", "permission": "VENDOR_MAINTAIN"},
            {"role": "SUPER", "permission": "PAYMENT_EXECUTE"},
        ]
        _, f = run([row("U1", "SUPER")], role_rows=roles)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["granted_by_roles"]["VENDOR_MAINTAIN"], ["SUPER"])

    def test_summary_counts_and_score(self):
        findings = [
            {"user_id": "U1", "severity": "Critical", "rule_id": "SOD-01"},
            {"user_id": "U1", "severity": "High", "rule_id": "SOD-02"},
        ]
        s = summarize({"U1": {}, "U2": {}}, findings)
        self.assertEqual(s["total_findings"], 2)
        self.assertEqual(s["users_with_findings"], 1)
        self.assertEqual(s["riskiest_users"][0], {"user_id": "U1", "risk_score": 15})

    # ---- Stage 5: exceptions and mitigating controls ----

    def _finding_with(self, exc_rows, today=date(2026, 10, 13)):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")])
        return apply_exceptions(f, load_exceptions(exc_rows), today)[0]

    def _exc(self, expiry, residual="Medium"):
        return [{"user_id": "U1", "rule_id": "SOD-01", "control_id": "C1",
                 "expiry_date": expiry, "residual_severity": residual}]

    def test_valid_exception_downgrades(self):
        f = self._finding_with(self._exc("2027-01-01"))
        self.assertEqual((f["status"], f["severity"], f["inherent_severity"]),
                         ("Mitigated", "Medium", "Critical"))

    def test_expired_exception_keeps_original_severity(self):
        f = self._finding_with(self._exc("2026-01-01"))
        self.assertEqual((f["status"], f["severity"]), ("Exception expired", "Critical"))

    def test_exception_cannot_raise_severity(self):
        rules = [dict(RULES[0], severity="Low")]
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")], rules=rules)
        r = apply_exceptions(f, load_exceptions(self._exc("2027-01-01", "Critical")),
                             date(2026, 10, 13))[0]
        self.assertEqual(r["severity"], "Low")

    def test_no_exception_stays_open(self):
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")])
        self.assertEqual(apply_exceptions(f, {})[0]["status"], "Open")

    # ---- Stage 6b: organizational conditions ----

    def test_overlap_same_org(self):
        self.assertTrue(org_overlap([{"1000"}, {"1000", "2000"}]))

    def test_overlap_different_org(self):
        self.assertFalse(org_overlap([{"1000"}, {"2000"}]))

    def test_overlap_wildcard_matches_any(self):
        self.assertTrue(org_overlap([{"1000"}, {"*"}]))

    def _org_case(self, vendor_org, payer_org, same_org):
        rows = [
            {"role": "VENDOR_ADMIN", "permission": "VENDOR_MAINTAIN", "org_unit": vendor_org},
            {"role": "PAYER", "permission": "PAYMENT_EXECUTE", "org_unit": payer_org},
        ]
        rules = [dict(RULES[0], same_org=same_org)]
        _, f = run([row("U1", "VENDOR_ADMIN"), row("U1", "PAYER")], role_rows=rows, rules=rules)
        return apply_org_conditions(f, rules, build_role_orgs(rows))

    def test_cross_org_suppressed_when_rule_requires_same_org(self):
        kept, suppressed = self._org_case("1000", "2000", "Y")
        self.assertEqual((len(kept), len(suppressed)), (0, 1))

    def test_cross_org_kept_when_rule_has_no_org_condition(self):
        kept, suppressed = self._org_case("1000", "2000", "N")
        self.assertEqual((len(kept), len(suppressed)), (1, 0))


if __name__ == "__main__":
    unittest.main()