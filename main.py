from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from app.gui.main_window import MainWindow
from app.utils.logging import configure_logging


def main() -> int:
    configure_logging()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
