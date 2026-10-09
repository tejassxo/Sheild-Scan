"""Technical Diagram Generator for ShieldScan.
Produces clean vector-quality PNG diagrams adhering strictly to the Apple/engineering color lock.
"""

from __future__ import annotations
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Color tokens
COLOR_CANVAS = "#F5F5F2"
COLOR_CARD = "#FFFFFF"
COLOR_BORDER = "#D2D2CC"
COLOR_TEXT_PRIMARY = "#1D1D1F"
COLOR_TEXT_MUTED = "#6E6E73"
COLOR_ACCENT = "#B42318"
COLOR_GREEN = "#2F6B4F"


def generate_architecture_diagram(output_path: Path) -> Path:
    """Generates clean system architecture diagram matching ShieldScan design tokens."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)
    fig.patch.set_facecolor(COLOR_CANVAS)
    ax.set_facecolor(COLOR_CANVAS)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 55)
    ax.axis("off")

    # Helper to draw rounded card
    def draw_box(x, y, w, h, title, subtitle="", is_accent=False, is_green=False):
        edge = COLOR_ACCENT if is_accent else (COLOR_GREEN if is_green else COLOR_BORDER)
        lw = 1.8 if (is_accent or is_green) else 1.0
        rect = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=1,rounding_size=2",
            facecolor=COLOR_CARD,
            edgecolor=edge,
            linewidth=lw
        )
        ax.add_patch(rect)
        ax.text(
            x + w / 2, y + h / 2 + (1.2 if subtitle else 0),
            title,
            ha="center", va="center",
            fontsize=10, fontweight="bold",
            color=COLOR_ACCENT if is_accent else (COLOR_GREEN if is_green else COLOR_TEXT_PRIMARY),
            fontfamily="sans-serif"
        )
        if subtitle:
            ax.text(
                x + w / 2, y + h / 2 - 1.8,
                subtitle,
                ha="center", va="center",
                fontsize=7.5,
                color=COLOR_TEXT_MUTED,
                fontfamily="sans-serif"
            )

    def draw_arrow(x1, y1, x2, y2):
        ax.annotate(
            "",
            xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(arrowstyle="->", color=COLOR_TEXT_MUTED, lw=1.2, shrinkA=3, shrinkB=3)
        )

    # 1. UI Layer
    draw_box(32, 45, 36, 7, "ShieldScan UI", "PyQt5 Light Engineering Interface · Apple-Inspired")
    draw_arrow(50, 45, 50, 39)

    # 2. Controller
    draw_box(32, 32, 36, 7, "Scan Controller", "Target Resolution · Concurrency · Event Dispatch")
    draw_arrow(50, 32, 50, 26)

    # 3. Engines (Scanner & Analysis)
    draw_box(4, 18, 42, 8, "Scanner Engine", "Host Discovery · Asynchronous Port Enumeration · Deep Service Fingerprinting")
    draw_box(54, 18, 42, 8, "Analysis & Intel Engine", "Evidence-Based Findings · CVE Correlation · Change Detection", is_accent=True)
    draw_arrow(40, 32, 25, 26)
    draw_arrow(60, 32, 75, 26)
    draw_arrow(46, 22, 54, 22)

    # 4. Canonical Model
    draw_arrow(25, 18, 40, 11)
    draw_arrow(75, 18, 60, 11)
    draw_box(28, 4, 44, 7, "Canonical ScanResult", "Single Source of Truth · Audit Records · Metrics", is_green=True)

    # 5. Output Consumers
    draw_arrow(34, 4, 15, -2)
    draw_arrow(50, 4, 50, -2)
    draw_arrow(66, 4, 85, -2)

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    return output_path


def generate_pipeline_diagram(output_path: Path) -> Path:
    """Generates the linear ShieldScan workflow pipeline diagram."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 2.5), dpi=300)
    fig.patch.set_facecolor(COLOR_CANVAS)
    ax.set_facecolor(COLOR_CANVAS)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 25)
    ax.axis("off")

    stages = [
        ("TARGET", "Scope Spec"),
        ("DISCOVER", "Host Ping"),
        ("SCAN", "Async Ports"),
        ("IDENTIFY", "Deep Banners"),
        ("ANALYZE", "Evidence Findings"),
        ("COMPARE", "Time Diff"),
        ("REPORT", "DOCX / PPTX"),
    ]

    x_step = 14
    box_w = 11.5
    for i, (stage, desc) in enumerate(stages):
        x = 2 + (i * x_step)
        y = 5
        is_highlight = (i == 4 or i == 6)
        rect = patches.FancyBboxPatch(
            (x, y), box_w, 15,
            boxstyle="round,pad=0.5,rounding_size=1.5",
            facecolor=COLOR_CARD,
            edgecolor=COLOR_ACCENT if is_highlight else COLOR_BORDER,
            linewidth=1.5 if is_highlight else 1.0
        )
        ax.add_patch(rect)
        ax.text(
            x + box_w / 2, y + 9.5,
            stage,
            ha="center", va="center",
            fontsize=8.5, fontweight="bold",
            color=COLOR_ACCENT if is_highlight else COLOR_TEXT_PRIMARY,
            fontfamily="sans-serif"
        )
        ax.text(
            x + box_w / 2, y + 4.5,
            desc,
            ha="center", va="center",
            fontsize=6.5,
            color=COLOR_TEXT_MUTED,
            fontfamily="sans-serif"
        )
        if i < len(stages) - 1:
            ax.annotate(
                "",
                xy=(x + box_w + 2.2, y + 7.5),
                xytext=(x + box_w + 0.3, y + 7.5),
                arrowprops=dict(arrowstyle="->", color=COLOR_TEXT_MUTED, lw=1.2)
            )

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    return output_path
