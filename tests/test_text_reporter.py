from agent_scan.reporters.text_reporter import human_report


def test_report_shows_other_languages_when_no_supported_files():
    results = {
        "target": "/tmp/go-mcp-server",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
        "other_languages": [
            {"language": "Go", "count": 146},
            {"language": "Shell", "count": 8},
        ],
    }
    out = human_report(results)
    assert "No Python or TypeScript files were found for analysis." in out
    assert "Go (146 files)" in out
    assert "Shell (8 files)" in out
    assert "agent-scan currently supports Python" in out


def test_report_shows_no_files_notice_when_nothing_found():
    results = {
        "target": "/tmp/no-python-project",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [],
    }
    out = human_report(results)
    assert "No Python or TypeScript files were found for analysis." in out


def test_report_shows_ts_notice_when_only_ts_found():
    results = {
        "target": "/tmp/ts-only-project",
        "num_files_scanned": 0,
        "findings": [],
        "capabilities": [],
        "risks": [],
        "ts_entry_points": [
            {"name": "read_file", "file": "src/tools.ts", "lineno": 10, "pattern_type": "mcp_tool", "confidence": 0.95}
        ],
    }
    out = human_report(results)
    assert "TypeScript Entry Points" in out
    assert "read_file" in out
    assert "Full capability analysis requires Python source" in out
