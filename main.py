"""ShieldScan Application Entry Point.
Launches the native Apple-inspired PyQt5 user interface or CLI engine.
"""

from __future__ import annotations
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from src.ui.main_window import MainWindow
from src.ui.styles import SHIELDSCAN_QSS
from src.cli import run_cli


def main():
    if len(sys.argv) > 1 and any(arg in sys.argv for arg in ["--target", "-t", "--cli", "--docx", "--pptx", "--help", "-h"]):
        run_cli()
        return

    # Enable High DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("ShieldScan")
    app.setStyleSheet(SHIELDSCAN_QSS)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
