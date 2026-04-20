import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import git

from analyze import PayloadAnalyzer, StructuralPayloadAnalyzer, print_report, save_json_report


def _make_analyzer(branch="feature", target="main"):
    with patch("git.Repo"):
        return PayloadAnalyzer("/fake/repo", branch, target)


SIMPLE_ORIGINAL = """
class Auth:
    def login(self): pass
    def logout(self): pass

class Database:
    def connect(self): pass
    def query(self): pass
    def disconnect(self): pass

class Cache:
    def get(self): pass
    def set(self): pass
"""

SIMPLE_MODIFIED = """
class Auth:
    def login(self): pass
"""


def _make_full_report(status="SAFE", files_deleted=0, lines_deleted=0):
    return {
        "timestamp": datetime.now().isoformat(),
        "analysis": {"branch": "feature", "target": "main", "repo_path": "."},
        "files": {
            "added": 3,
            "deleted": files_deleted,
            "modified": 2,
            "renamed": 0,
            "copied": 0,
            "type_changed": 0,
            "total_changed": 3 + files_deleted + 2,
        },
        "lines": {
            "added": 100,
            "deleted": lines_deleted,
            "net_change": 100 - lines_deleted,
            "deletion_ratio_percent": 0.0,
            "codebase_reduction_percent": 0.0,
        },
        "temporal": {
            "branch_age_days": 5,
            "branch_last_commit": datetime.now().isoformat(),
            "branch_commit_hash": "abc1234",
            "target_last_commit": datetime.now().isoformat(),
            "target_commit_hash": "def5678",
        },
        "verdict": {
            "status": status,
            "severity": "LOW",
            "flags": ["No major red flags detected"],
            "recommendation": "✓ Proceed with normal review process",
            "severity_score": 0,
        },
        "deleted_files": {"total": files_deleted, "critical": [], "all": []},
        "structural": {"score": 0.0, "flagged_files": []},
    }


class TestStructuralPayloadAnalyzer(unittest.TestCase):
    def test_no_deletions_score_is_zero(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertEqual(result['score'], 0.0)
        self.assertEqual(result['metrics']['deleted_node_count'], 0)

    def test_detects_deleted_classes(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED).analyze_structural_drift()
        self.assertIn('Database', result['deleted_components'])
        self.assertIn('Cache', result['deleted_components'])

    def test_score_scales_with_deletion_ratio(self):
        full_delete = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "").analyze_structural_drift()
        partial = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, SIMPLE_MODIFIED).analyze_structural_drift()
        self.assertGreater(full_delete['score'], partial['score'])

    def test_confidence_suppresses_tiny_files(self):
        tiny_original = "def foo(): pass\ndef bar(): pass"
        tiny_modified = "def foo(): pass"
        result = StructuralPayloadAnalyzer(tiny_original, tiny_modified).analyze_structural_drift()
        self.assertLess(result['score'], 1.0)

    def test_full_confidence_at_10_nodes(self):
        result = StructuralPayloadAnalyzer(SIMPLE_ORIGINAL, "").analyze_structural_drift()
        self.assertEqual(result['score'], 3.0)

    def test_syntax_error_returns_error_key(self):
        result = StructuralPayloadAnalyzer("def foo(: pass", "valid = 1").analyze_structural_drift()
        self.assertIn('error', result)

    def test_added_components_tracked(self):
        result = StructuralPayloadAnalyzer(SIMPLE_MODIFIED, SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertIn('Database', result['added_components'])

    def test_empty_original_no_crash(self):
        result = StructuralPayloadAnalyzer("", SIMPLE_ORIGINAL).analyze_structural_drift()
        self.assertEqual(result['metrics']['deleted_node_count'], 0)
        self.assertEqual(result['score'], 0.0)


class TestAssessConsequenceSafe(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_no_changes_is_safe(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertEqual(v["status"], "SAFE")
        self.assertEqual(v["severity_score"], 0)

    def test_safe_has_recommendation(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertIn("recommendation", v)
        self.assertIn("flags", v)


class TestAssessConsequenceReview(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_90_days(self):
        v = self.a._assess_consequence(0, 0, 91, 0)
        self.assertEqual(v["status"], "REVIEW")
        self.assertEqual(v["severity_score"], 1)

    def test_11_files_deleted(self):
        v = self.a._assess_consequence(11, 0, 0, 0)
        self.assertEqual(v["status"], "REVIEW")

    def test_deletion_ratio_over_50(self):
        v = self.a._assess_consequence(0, 0, 0, 55)
        self.assertEqual(v["status"], "REVIEW")

    def test_5001_lines_deleted(self):
        v = self.a._assess_consequence(0, 5001, 0, 0)
        self.assertEqual(v["status"], "REVIEW")


class TestAssessConsequenceCaution(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_180_days_plus_minor_flag(self):
        v = self.a._assess_consequence(11, 0, 185, 0)
        self.assertEqual(v["status"], "CAUTION")
        self.assertGreaterEqual(v["severity_score"], 3)

    def test_over_20_files_plus_old_branch(self):
        v = self.a._assess_consequence(25, 0, 91, 0)
        self.assertEqual(v["status"], "CAUTION")

    def test_deletion_ratio_over_70_plus_minor_flag(self):
        v = self.a._assess_consequence(11, 0, 0, 75)
        self.assertEqual(v["status"], "CAUTION")

    def test_over_10000_lines_plus_old_branch(self):
        v = self.a._assess_consequence(0, 10001, 91, 0)
        self.assertEqual(v["status"], "CAUTION")


class TestAssessConsequenceDestructive(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_branch_over_365_days_and_many_files(self):
        v = self.a._assess_consequence(60, 0, 400, 0)
        self.assertEqual(v["status"], "DESTRUCTIVE")
        self.assertEqual(v["severity"], "CRITICAL")

    def test_high_deletion_ratio_and_line_count(self):
        v = self.a._assess_consequence(0, 15000, 10, 95)
        self.assertEqual(v["status"], "DESTRUCTIVE")

    def test_combined_flags_score(self):
        v = self.a._assess_consequence(60, 60000, 400, 95)
        self.assertGreaterEqual(v["severity_score"], 5)
        self.assertGreater(len(v["flags"]), 1)

    def test_recommendation_says_do_not_merge(self):
        v = self.a._assess_consequence(60, 60000, 400, 95)
        self.assertIn("DO NOT MERGE", v["recommendation"])


class TestAssessConsequenceStructural(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_structural_score_below_threshold_no_flag(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_score=0.3)
        self.assertNotIn('Structural drift', ' '.join(v['flags']))

    def test_structural_score_above_half_adds_flag(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_score=0.6)
        self.assertIn('Structural drift', ' '.join(v['flags']))

    def test_high_structural_score_elevates_verdict(self):
        v = self.a._assess_consequence(0, 0, 0, 0, structural_score=3.0)
        self.assertIn(v['status'], ('CAUTION', 'DESTRUCTIVE'))

    def test_structural_score_adds_to_severity(self):
        v_without = self.a._assess_consequence(0, 0, 0, 0, structural_score=0.0)
        v_with = self.a._assess_consequence(0, 0, 0, 0, structural_score=1.5)
        self.assertGreater(v_with['severity_score'], v_without['severity_score'])

    def test_default_structural_score_is_zero(self):
        v = self.a._assess_consequence(0, 0, 0, 0)
        self.assertEqual(v['status'], 'SAFE')


class TestPayloadAnalyzerInit(unittest.TestCase):
    def test_bad_repo_path_exits(self):
        with self.assertRaises(SystemExit):
            PayloadAnalyzer("/this/does/not/exist", "branch", "main")

    def test_stores_branch_and_target(self):
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "my-branch", "develop")
        self.assertEqual(a.branch, "my-branch")
        self.assertEqual(a.target, "develop")

    def test_default_target_is_main(self):
        with patch("git.Repo"):
            a = PayloadAnalyzer("/fake", "feature")
        self.assertEqual(a.target, "main")


class TestAnalyzeErrors(unittest.TestCase):
    def setUp(self):
        self.a = _make_analyzer()

    def test_missing_target_branch_returns_error(self):
        self.a.repo.commit.side_effect = git.exc.BadName("main")
        result = self.a.analyze()
        self.assertIn("error", result)
        self.assertIn("main", result["error"])

    def test_missing_feature_branch_returns_error(self):
        call_count = {"n": 0}

        def commit_side_effect(branch):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise git.exc.BadName(branch)
            return MagicMock()

        self.a.repo.commit.side_effect = commit_side_effect
        result = self.a.analyze()
        self.assertIn("error", result)

    def test_error_includes_available_branches(self):
        self.a.repo.commit.side_effect = git.exc.BadName("main")
        self.a.repo.heads = []
        result = self.a.analyze()
        self.assertIn("available_branches", result)


class TestAnalyzeSuccess(unittest.TestCase):
    def _build_mock_diff(self, change_type, content=None):
        d = MagicMock()
        d.change_type = change_type
        if change_type == "A":
            d.b_blob.data_stream.read.return_value = (content or "line1\nline2\n").encode()
        elif change_type == "D":
            d.a_blob.data_stream.read.return_value = (content or "line1\nline2\n").encode()
            d.a_path = "src/deleted_file.py"
        return d

    def _setup_repo(self, diffs):
        a = _make_analyzer()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 3, 1, tzinfo=timezone.utc)

        branch_commit = MagicMock()
        branch_commit.committed_datetime = t1
        branch_commit.hexsha = "aabbccddeeff"

        target_commit = MagicMock()
        target_commit.committed_datetime = t2
        target_commit.hexsha = "112233445566"

        def commit_side_effect(ref):
            if ref == "main":
                return target_commit
            return branch_commit

        a.repo.commit.side_effect = commit_side_effect

        merge_base_commit = MagicMock()
        merge_base_commit.diff.return_value = diffs
        a.repo.merge_base.return_value = [merge_base_commit]

        return a

    def test_report_has_required_keys(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertNotIn("error", result)
        for key in ("timestamp", "analysis", "files", "lines", "temporal", "verdict", "deleted_files"):
            self.assertIn(key, result)

    def test_counts_modified_files(self):
        diffs = [self._build_mock_diff("M"), self._build_mock_diff("M")]
        a = self._setup_repo(diffs)
        result = a.analyze()
        self.assertEqual(result["files"]["modified"], 2)

    def test_counts_deleted_files(self):
        diffs = [self._build_mock_diff("D"), self._build_mock_diff("D")]
        a = self._setup_repo(diffs)
        result = a.analyze()
        self.assertEqual(result["files"]["deleted"], 2)

    def test_counts_added_lines(self):
        a = self._setup_repo([self._build_mock_diff("A", "a\nb\nc\n")])
        result = a.analyze()
        self.assertGreater(result["lines"]["added"], 0)

    def test_counts_deleted_lines(self):
        a = self._setup_repo([self._build_mock_diff("D", "x\ny\n")])
        result = a.analyze()
        self.assertGreater(result["lines"]["deleted"], 0)

    def test_verdict_is_present(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertIn(result["verdict"]["status"], ("SAFE", "REVIEW", "CAUTION", "DESTRUCTIVE"))

    def test_critical_deletions_flagged(self):
        d = self._build_mock_diff("D")
        d.a_path = "tests/test_core.py"
        a = self._setup_repo([d])
        result = a.analyze()
        self.assertIn("tests/test_core.py", result["deleted_files"]["critical"])

    def test_deleted_files_list(self):
        d = self._build_mock_diff("D")
        d.a_path = "src/module.py"
        a = self._setup_repo([d])
        result = a.analyze()
        self.assertIn("src/module.py", result["deleted_files"]["all"])

    def test_deletion_ratio_zero_when_no_changes(self):
        a = self._setup_repo([self._build_mock_diff("M")])
        result = a.analyze()
        self.assertEqual(result["lines"]["deletion_ratio_percent"], 0.0)


class TestPrintReport(unittest.TestCase):
    def test_error_report_prints_failed(self):
        report = {"error": "Branch not found", "error_type": "BadName"}
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("ANALYSIS FAILED", out.getvalue())
        self.assertIn("Branch not found", out.getvalue())

    def test_error_with_available_branches(self):
        report = {"error": "Not found", "available_branches": ["main", "dev"]}
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("main", out.getvalue())

    def test_full_report_shows_branch_names(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report())
        output = out.getvalue()
        self.assertIn("feature", output)
        self.assertIn("main", output)

    def test_full_report_shows_verdict(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report(status="DESTRUCTIVE"))
        self.assertIn("DESTRUCTIVE", out.getvalue())

    def test_deleted_files_section_shown_when_present(self):
        report = _make_full_report(files_deleted=2)
        report["deleted_files"]["all"] = ["src/a.py", "src/b.py"]
        report["deleted_files"]["critical"] = ["src/a.py"]
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(report)
        self.assertIn("src/a.py", out.getvalue())

    def test_no_deleted_files_section_when_empty(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            print_report(_make_full_report(files_deleted=0))
        self.assertNotIn("DELETED FILES", out.getvalue())


class TestSaveJsonReport(unittest.TestCase):
    def test_saves_valid_json(self):
        report = {"status": "SAFE", "score": 0}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_json_report(report, path)
            with open(path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["status"], "SAFE")
        finally:
            os.unlink(path)

    def test_gracefully_handles_write_error(self):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            save_json_report({"x": 1}, "/bad/path.json")


if __name__ == "__main__":
    unittest.main()
