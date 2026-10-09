"""Design tokens for ShieldScan.
Strictly adheres to Apple-inspired minimalism and the Color Lock Directive.
"""

from __future__ import annotations

# Exact Color Lock Tokens
C_CANVAS            = "#F5F5F2"  # Canvas background
C_SURFACE_PRIMARY   = "#FFFFFF"  # Primary cards, inputs, dialogs
C_SURFACE_SECONDARY = "#F0F0EC"  # Secondary surfaces, table headers, hover
C_SURFACE_TERTIARY  = "#E8E8E2"  # Active elements, borders subtle

C_TEXT_PRIMARY      = "#1D1D1F"  # Deep charcoal body text
C_TEXT_SECONDARY    = "#6E6E73"  # Muted secondary labels
C_TEXT_MUTED        = "#86868B"  # Subtitles, placeholder text

C_BORDER            = "#D2D2CC"  # Clean neutral hairline border
C_BORDER_LIGHT      = "#E5E5E0"  # Subtle dividers

# Semantic Accents
C_ACCENT            = "#B42318"  # Primary ShieldScan Vermilion / Deep Red
C_ACCENT_HOVER      = "#991B1B"  # Darker vermilion
C_ACCENT_LIGHT      = "#FDF2F2"  # Subtle light red wash

C_POSITIVE          = "#2F6B4F"  # Muted green (Open, Reachable)
C_POSITIVE_LIGHT    = "#F0F7F3"  # Subtle green wash

C_WARNING           = "#9A6700"  # Muted amber (Medium, Filtered)
C_WARNING_LIGHT     = "#FEF9EE"  # Subtle amber wash

C_CRITICAL          = "#B42318"  # Critical / High findings

# Typography Stacks
FONT_FAMILY_PRIMARY = "Segoe UI, -apple-system, BlinkMacSystemFont, 'Inter', 'SF Pro Display', sans-serif"
FONT_FAMILY_MONO    = "'Cascadia Code', 'Consolas', 'JetBrains Mono', 'IBM Plex Mono', monospace"
