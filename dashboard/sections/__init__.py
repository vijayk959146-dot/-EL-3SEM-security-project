"""
Modular UI sections for the Field Report security dashboard.
"""

from dashboard.sections.summary import render_summary_section
from dashboard.sections.findings import render_findings_section
from dashboard.sections.exposure import render_exposure_section
from dashboard.sections.fixes import render_fixes_section
from dashboard.sections.evidence import render_evidence_section
from dashboard.sections.copilot import render_copilot_panel

__all__ = [
    "render_summary_section",
    "render_findings_section",
    "render_exposure_section",
    "render_fixes_section",
    "render_evidence_section",
    "render_copilot_panel",
]
