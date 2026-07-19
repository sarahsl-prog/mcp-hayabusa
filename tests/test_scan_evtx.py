#!/usr/bin/env python3
"""Imports server.py and calls scan_evtx directly. Runs standalone or under pytest."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner
import server

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "CA_DCSync_4662.evtx"


def test_scan_evtx_finds_dcsync():
    result = server.scan_evtx(str(FIXTURE))
    assert "error" not in result, result.get("error")
    assert result["finding_count"] > 0
    assert any("DC Sync" in f["RuleTitle"] for f in result["findings"])


def test_scan_evtx_missing_file():
    result = server.scan_evtx("/tmp/does-not-exist.evtx")
    assert "error" in result
    assert "not found" in result["error"].lower()


def test_scan_evtx_rule_filter_matches():
    result = server.scan_evtx(str(FIXTURE), rule_filter="mimikatz")
    assert "error" not in result, result.get("error")
    assert result["finding_count"] > 0
    assert all("mimikatz" in f["RuleTitle"].lower() for f in result["findings"])


def test_scan_evtx_rule_filter_no_match():
    result = server.scan_evtx(str(FIXTURE), rule_filter="nonexistentxyz")
    assert "error" not in result, result.get("error")
    assert result["finding_count"] == 0
    assert result["findings"] == []


def test_scan_evtx_max_results_caps_returned_but_not_total():
    full = server.scan_evtx(str(FIXTURE))
    capped = server.scan_evtx(str(FIXTURE), max_results=1)
    assert "error" not in capped, capped.get("error")
    assert capped["returned_count"] == 1
    assert capped["finding_count"] == full["finding_count"]
    assert len(capped["findings"]) == 1


def test_scan_evtx_output_format_summary_trims_fields():
    result = server.scan_evtx(str(FIXTURE), output_format="summary")
    assert "error" not in result, result.get("error")
    finding = result["findings"][0]
    assert set(finding.keys()) <= set(scanner._SUMMARY_FIELDS)
    assert "Details" not in finding


def test_scan_evtx_output_format_full_keeps_all_fields():
    result = server.scan_evtx(str(FIXTURE), output_format="full")
    assert "error" not in result, result.get("error")
    finding = result["findings"][0]
    assert "Details" in finding
    assert "ExtraFieldInfo" in finding


def test_scan_evtx_invalid_output_format():
    result = server.scan_evtx(str(FIXTURE), output_format="bogus")
    assert "error" in result
    assert "output_format" in result["error"]


def main() -> int:
    print(f"Scanning {FIXTURE} ...")
    result = server.scan_evtx(str(FIXTURE))
    print(json.dumps(result, indent=2))

    if "error" in result:
        print(f"FAIL: scan returned an error: {result['error']}")
        return 1

    if result["finding_count"] <= 0:
        print("FAIL: expected at least one finding from the DCSync sample")
        return 1

    print(f"OK: {result['finding_count']} finding(s)")

    print("\nScanning nonexistent file ...")
    error_result = server.scan_evtx("/tmp/does-not-exist.evtx")
    if "error" not in error_result:
        print("FAIL: expected an error for a nonexistent file")
        return 1
    print(f"OK: got expected error: {error_result['error']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
