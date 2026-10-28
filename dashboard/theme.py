"""
Theme injector for Field Report design system.
Loads dashboard/theme.css and manages light/dark mode tokens.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import streamlit as st

THEME_CSS_PATH = Path(__file__).resolve().parent / "theme.css"

LIGHT_TOKENS = {
    "bg_app": "#F6F3EC",
    "bg_surface": "#FFFFFF",
    "bg_subtle": "#EFECE4",
    "bg_hover": "#E7E3D8",
    "text_ink": "#1B1B1B",
    "text_muted": "#5C5A55",
    "text_subtle": "#8C887F",
    "border_hairline": "#D9D4C7",
    "border_strong": "#BCB6A6",
    "accent": "#D8431F",
    "accent_subtle": "#FBECE8",
    "accent_hover": "#BF360C",
    "sev_crit": "#991B1B",
    "sev_high": "#C2410C",
    "sev_med": "#B45309",
    "sev_low": "#2563EB",
    "sev_info": "#64748B",
}

DARK_TOKENS = {
    "bg_app": "#16171A",
    "bg_surface": "#1E2024",
    "bg_subtle": "#26282E",
    "bg_hover": "#2F323A",
    "text_ink": "#E5E5E5",
    "text_muted": "#A3A3A3",
    "text_subtle": "#737373",
    "border_hairline": "#2C2D32",
    "border_strong": "#3F4148",
    "accent": "#E0532E",
    "accent_subtle": "#2A1C19",
    "accent_hover": "#FF6B47",
    "sev_crit": "#DC2626",
    "sev_high": "#EA580C",
    "sev_med": "#D97706",
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
        div[data-baseweb="select"] > div,
        div[data-baseweb="input"] > div {{
          background-color: {tokens['bg_surface']} !important;
          color: {tokens['text_ink']} !important;
          border-color: {tokens['border_hairline']} !important;
        }}
        [data-testid="stExpander"] {{
          background-color: {tokens['bg_surface']} !important;
          border-color: {tokens['border_hairline']} !important;
        }}
        </style>
        """
        st.markdown(dark_override, unsafe_allow_html=True)
