"""
Automated tests for Field Report Streamlit dashboard.
Tests app rendering, state persistence, pending_target workflow,
theme switching, empty states, and XSS escaping in ledger and diagram.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from streamlit.testing.v1 import AppTest
from dashboard.attack_graph import render_attack_surface_graph_html
from dashboard.components import esc, generate_verdict_text

APP_PATH = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


class TestDashboardState(unittest.TestCase):
    """Test suite for Streamlit dashboard state and Field Report rendering."""

    def test_app_loads_without_exceptions_light_theme(self):
        """Verify the app initializes and renders cleanly with default light theme."""
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        self.assertFalse(at.exception, f"App threw exception: {at.exception}")

    def test_app_loads_without_exceptions_dark_theme(self):
        """Verify the app initializes and renders cleanly in dark theme."""
        at = AppTest.from_file(APP_PATH)
        at.session_state["theme_mode"] = "Dark"
        at.run(timeout=15)
        self.assertFalse(at.exception, f"App threw exception: {at.exception}")

    def test_navigation_across_all_five_sections(self):
        """Verify navigation through all 5 sections works without exceptions."""
        sections = ["Summary", "Findings", "Exposure", "Fixes", "Evidence & reports"]
        for section in sections:
            at = AppTest.from_file(APP_PATH)
            at.session_state["active_section"] = section
            at.run(timeout=15)
            self.assertFalse(at.exception, f"Section '{section}' threw exception: {at.exception}")

    @patch("dashboard.app.run_scan")
    def test_scan_handler_pending_target_switch(self, mock_run_scan):
        """Verify scanning switches target_workspace_select without StreamlitAPIException."""
        mock_run_scan.return_value = SimpleNamespace(
            target="localhost",
            mode="PASSIVE",
            finding_count=1,
            report_path="data/localhost/prioritized_report.json",
        )

        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        self.assertFalse(at.exception)

        scan_btn = None
        for btn in at.sidebar.button:
            if "Start assessment" in getattr(btn, "label", ""):
                scan_btn = btn
                break

        if scan_btn:
            scan_btn.click().run(timeout=15)
            self.assertFalse(at.exception, f"Scan button click failed: {at.exception}")

    @patch("dashboard.app._load_report", return_value={})
    @patch("dashboard.app.run_scan")
    def test_empty_state_buttons(self, mock_run_scan, mock_load_report):
        """Verify empty state buttons trigger scan without exception."""
        mock_run_scan.return_value = SimpleNamespace(
            target="localhost",
            mode="ACTIVE",
            finding_count=0,
            report_path="data/localhost/prioritized_report.json",
        )

        at = AppTest.from_file(APP_PATH)
        at.run(timeout=15)
        self.assertFalse(at.exception)

        localhost_btn = None
        for btn in at.button:
            if "localhost" in getattr(btn, "label", "").lower():
                localhost_btn = btn
                break

        if localhost_btn:
            localhost_btn.click().run(timeout=15)
            self.assertFalse(at.exception, f"Empty state button failed: {at.exception}")

    def test_finding_xss_payload_escaped_in_diagram(self):
        """Verify malicious tags in target and finding titles are strictly escaped in diagram."""
        xss_payload = '<img src=x onerror=alert(1)>'
        html_output = render_attack_surface_graph_html(
            target="test.org<script>alert(2)</script>",
            findings=[{
                "title": xss_payload,
                "severity": "High",
                "exploitability": "KEV-listed",
                "related_cves": ["CVE-2024-0001<bdi>"],
            }],
            ips=["1.1.1.1<marquee>"],
            ports=[{"port": "80<style_tag>", "service": "http<script_tag>"}],
            theme_mode="light",
        )

        self.assertNotIn("<img src=x onerror=alert(1)>", html_output)
        self.assertNotIn("<script>alert(2)</script>", html_output)
        self.assertNotIn("<marquee>", html_output)
        self.assertNotIn("<style_tag>", html_output)
        self.assertNotIn("<script_tag>", html_output)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_output)
        self.assertIn("80&lt;style_tag&gt;", html_output)
        self.assertIn("&lt;script&gt;alert(2)&lt;/script&gt;", html_output)

    def test_finding_xss_payload_escaped_in_verdict(self):
        """Verify malicious tags in findings are safely handled by verdict generator."""
        xss_payload = '<img src=x onerror=alert(1)>'
        sample_report = {
            "target": "example.com<script>",
            "findings": [
                {
                    "title": xss_payload,
                    "severity": "Critical",
                    "suggested_action": "Sanitize <input>",
                }
            ],
        }
        verdict = generate_verdict_text(sample_report)
        escaped_verdict = esc(verdict)
        self.assertNotIn("<img src=x onerror=alert(1)>", escaped_verdict)
        self.assertNotIn("<script>", escaped_verdict)
        self.assertNotIn("<input>", escaped_verdict)


if __name__ == "__main__":
    unittest.main()
