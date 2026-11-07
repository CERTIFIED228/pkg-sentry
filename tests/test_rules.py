from pkg_sentry.rules import RULES, Finding, judge, snippet


def test_nothing_found_is_none():
    verdict = judge([])
    assert (verdict.score, verdict.severity) == (0, "none")


def test_points_add_up_into_severity():
    assert judge([Finding("shell", "x")]).severity == "none"            # 5
    assert judge([Finding("recon", "x"), Finding("shell", "x")]).severity == "low"  # 15
    assert judge([Finding("typosquat", "x")]).severity == "medium"       # 35
    assert judge([Finding("exec-decoded", "x"), Finding("raw-ip-url", "x")]).severity == "high"


def test_a_rule_counts_once_however_often_it_fires():
    many = [Finding("raw-ip-url", f"ip {i}", path="a.py", line=i) for i in range(10)]
    verdict = judge(many)
    assert verdict.score == RULES["raw-ip-url"][0]
    assert len(verdict.findings) == 10  # all kept as evidence


def test_strongest_finding_of_a_rule_counts():
    verdict = judge([Finding("install-script", "weak", points=5), Finding("install-script", "x")])
    assert verdict.score == RULES["install-script"][0]


def test_score_is_capped():
    every = [Finding(rule, rule) for rule in RULES]
    assert judge(every).score == 100


def test_behaviour_alone_never_goes_past_medium():
    busy = [Finding(r, r) for r in ("install-script", "shell-at-install", "network-at-install",
                                    "binary-payload", "no-source")]
    verdict = judge(busy)
    assert verdict.score == 45 and verdict.severity == "medium"


def test_evidence_on_top_of_behaviour_counts_in_full():
    found = [Finding("shell-at-install", "x"), Finding("network-at-install", "x"),
             Finding("exfil-endpoint", "x")]
    assert judge(found).score == 45 + 30


def test_critical_findings_make_it_critical():
    verdict = judge([Finding("exfil-endpoint", "discord webhook", critical=True)])
    assert verdict.severity == "critical"
    assert verdict.score >= 90


def test_findings_are_ordered_strongest_first():
    verdict = judge([Finding("shell", "a"), Finding("exec-decoded", "b"), Finding("recon", "c")])
    assert [f.rule for f in verdict.findings] == ["exec-decoded", "recon", "shell"]


def test_at_least():
    verdict = judge([Finding("typosquat", "x")])
    assert verdict.at_least("low") and verdict.at_least("medium")
    assert not verdict.at_least("high")


def test_where():
    assert Finding("shell", "x", path="setup.py", line=3).where == "setup.py:3"
    assert Finding("shell", "x", path="setup.py").where == "setup.py"
    assert Finding("shell", "x").where == ""


def test_snippet():
    assert snippet("exec(\n    base64.b64decode(x))") == "exec( base64.b64decode(x))"
    long = snippet("a" * 500)
    assert len(long) == 120 and long.endswith("...")
