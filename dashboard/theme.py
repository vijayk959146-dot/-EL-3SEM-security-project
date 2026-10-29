"""
Theme injector for Modern Enterprise SecOps design system.
Loads dashboard/theme.css and manages light/dark mode tokens.
Replaces AI-like retro-paper / serif styling with clean, production cybersecurity SaaS tokens.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import streamlit as st

THEME_CSS_PATH = Path(__file__).resolve().parent / "theme.css"

LIGHT_TOKENS = {
    "bg_app": "#F8FAFC",
    "bg_surface": "#FFFFFF",
    "bg_subtle": "#F1F5F9",
    "bg_hover": "#E2E8F0",
    "text_ink": "#0F172A",
    "text_muted": "#475569",
    "text_subtle": "#94A3B8",
    "border_hairline": "#E2E8F0",
    "border_strong": "#CBD5E1",
    "accent": "#2563EB",
    "accent_subtle": "#EFF6FF",
    "accent_hover": "#1D4ED8",
    "sev_crit": "#DC2626",
    "sev_high": "#EA580C",
    "sev_med": "#D97706",
    "sev_low": "#2563EB",
    "sev_info": "#64748B",
}

DARK_TOKENS = {
    "bg_app": "#0B0F19",
    "bg_surface": "#111827",
    "bg_subtle": "#1F2937",
    "bg_hover": "#374151",
    "text_ink": "#F9FAFB",
    "text_muted": "#9CA3AF",
    "text_subtle": "#6B7280",
    "border_hairline": "#1F2937",
    "border_strong": "#374151",
    "accent": "#3B82F6",
    "accent_subtle": "#1E3A8A33",
    "accent_hover": "#60A5FA",
    "sev_crit": "#EF4444",
    "sev_high": "#F97316",
    "sev_med": "#F59E0B",
    "sev_low": "#60A5FA",
    "sev_info": "#94A3B8",
}


def get_theme_tokens(mode: str = "light") -> dict[str, str]:
    """Return dictionary of theme tokens for specified mode."""
    if mode.lower() == "dark":
        return DARK_TOKENS.copy()
    return LIGHT_TOKENS.copy()


def apply_theme(mode: str = "light") -> None:
    """Inject base theme.css and dynamic mode overrides into Streamlit."""
    if not THEME_CSS_PATH.exists():
        return

    base_css = THEME_CSS_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{base_css}</style>", unsafe_allow_html=True)

    if mode.lower() == "dark":
        tokens = DARK_TOKENS
        dark_override = f"""
        <style>
        :root {{
          --bg-app: {tokens['bg_app']} !important;
          --bg-surface: {tokens['bg_surface']} !important;
          --bg-subtle: {tokens['bg_subtle']} !important;
          --bg-hover: {tokens['bg_hover']} !important;
          --text-ink: {tokens['text_ink']} !important;
          --text-muted: {tokens['text_muted']} !important;
          --text-subtle: {tokens['text_subtle']} !important;
          --border-hairline: {tokens['border_hairline']} !important;
          --border-strong: {tokens['border_strong']} !important;
          --accent: {tokens['accent']} !important;
          --accent-subtle: {tokens['accent_subtle']} !important;
          --accent-hover: {tokens['accent_hover']} !important;
          --sev-crit: {tokens['sev_crit']} !important;
          --sev-high: {tokens['sev_high']} !important;
          --sev-med: {tokens['sev_med']} !important;
          --sev-low: {tokens['sev_low']} !important;
          --sev-info: {tokens['sev_info']} !important;
        }}
        html, body, [data-testid="stAppViewContainer"] {{
          background-color: {tokens['bg_app']} !important;
          color: {tokens['text_ink']} !important;
        }}
        [data-testid="stSidebar"] {{
          background-color: {tokens['bg_subtle']} !important;
          border-right-color: {tokens['border_hairline']} !important;
        }}
        </style>
        """
        st.markdown(dark_override, unsafe_allow_html=True)
