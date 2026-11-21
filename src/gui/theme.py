"""Colour palettes + Qt style sheet (sharp, high-contrast workstation look)."""

DARK = {
    "bg": "#0e1116", "panel": "#141921", "panel2": "#1a2029", "panel3": "#212935",
    "border": "#2b3542", "border_hi": "#3b4859",
    "text": "#dce2ea", "muted": "#8a95a5", "faint": "#5d6877",
    "accent": "#3d8bfd", "accent_hi": "#5b9dff", "accent_lo": "#1d3b66",
    "ok": "#3fb950", "warn": "#d6a01d", "err": "#f0524a", "info": "#58a6ff",
    "sel": "#1f3a5f", "input": "#0b0e13",
    # RAM animation cell colours by stage type
    "cell_idle": "#252f3c", "cell_done": "#2c3a4d", "scan": "#3d8bfd",
    "symbols": "#22a39a", "extract": "#d6a01d", "hit": "#f0524a", "report": "#7d8fa8",
}
LIGHT = {
    "bg": "#eef0f3", "panel": "#ffffff", "panel2": "#f5f6f8", "panel3": "#e9ecf0",
    "border": "#c9cfd8", "border_hi": "#aab3bf",
    "text": "#141a22", "muted": "#566170", "faint": "#8b95a3",
    "accent": "#0f62d6", "accent_hi": "#2a76e8", "accent_lo": "#d6e4fb",
    "ok": "#1a7f37", "warn": "#9a6700", "err": "#cf222e", "info": "#0969da",
    "sel": "#cfe0fa", "input": "#ffffff",
    "cell_idle": "#dde2e8", "cell_done": "#b7c3d3", "scan": "#0f62d6",
    "symbols": "#0f8a80", "extract": "#b07d00", "hit": "#cf222e", "report": "#6b7c93",
}


def palette(name: str) -> dict:
    return LIGHT if name == "light" else DARK


def stylesheet(c: dict) -> str:
    return f"""
* {{ outline: 0; }}
QWidget {{ background: {c['bg']}; color: {c['text']};
          font-family: "Segoe UI", "Inter", sans-serif; font-size: 9.5pt; }}
QMainWindow::separator {{ background: {c['border']}; width: 1px; height: 1px; }}
QToolTip {{ background: {c['panel3']}; color: {c['text']}; border: 1px solid {c['border_hi']};
           padding: 6px; border-radius: 0; }}
QFrame#Panel, QWidget#Panel {{ background: {c['panel']}; border: 1px solid {c['border']}; }}
QLabel#H1 {{ font-size: 15pt; font-weight: 600; background: transparent; }}
QLabel#H2 {{ font-size: 11pt; font-weight: 600; background: transparent; }}
QLabel#Muted {{ color: {c['muted']}; background: transparent; }}
QLabel#Section {{ color: {c['muted']}; background: transparent; font-size: 8pt; font-weight: 600;
                 border-bottom: 1px solid {c['border']}; padding: 2px 0 1px 0; }}
QLabel#Stat {{ font-size: 18pt; font-weight: 600; background: transparent; }}
QLabel {{ background: transparent; }}

QPushButton {{ background: {c['panel3']}; color: {c['text']}; border: 1px solid {c['border_hi']};
              border-radius: 0; padding: 6px 14px; min-height: 18px; }}
QPushButton:hover {{ border-color: {c['accent']}; background: {c['panel2']}; }}
QPushButton:pressed {{ background: {c['accent_lo']}; }}
QPushButton:disabled {{ color: {c['faint']}; border-color: {c['border']}; background: {c['panel2']}; }}
QPushButton#Primary {{ background: {c['accent']}; color: #ffffff; border: 1px solid {c['accent']};
                      font-weight: 600; }}
QPushButton#Primary:hover {{ background: {c['accent_hi']}; }}
QPushButton#Primary:disabled {{ background: {c['accent_lo']}; color: {c['muted']}; }}
QPushButton#Danger {{ border-color: {c['err']}; color: {c['err']}; }}
QToolButton {{ background: transparent; border: 1px solid transparent; border-radius: 0;
              padding: 4px 6px; color: {c['text']}; }}
QToolButton:hover {{ border-color: {c['border_hi']}; background: {c['panel3']}; }}
QToolButton:checked {{ background: {c['accent_lo']}; border-color: {c['accent']}; }}
QToolButton#Help {{ padding: 0; border: none; }}
QToolButton#Help:hover {{ background: transparent; }}

QToolBar {{ background: {c['panel']}; border: none; border-bottom: 1px solid {c['border']};
           spacing: 2px; padding: 3px; }}
QToolBar::separator {{ background: {c['border']}; width: 1px; margin: 4px 6px; }}
QToolBar QWidget#Spacer {{ background: transparent; }}
QStatusBar {{ background: {c['panel']}; border-top: 1px solid {c['border']}; color: {c['muted']}; }}
QStatusBar::item {{ border: none; }}
QMenuBar {{ background: {c['panel']}; border-bottom: 1px solid {c['border']}; }}
QMenuBar::item {{ padding: 4px 10px; background: transparent; }}
QMenuBar::item:selected {{ background: {c['panel3']}; }}
QMenu {{ background: {c['panel']}; border: 1px solid {c['border_hi']}; padding: 2px; }}
QMenu::item {{ padding: 5px 24px 5px 22px; }}
QMenu::item:selected {{ background: {c['sel']}; }}
QMenu::separator {{ height: 1px; background: {c['border']}; margin: 3px 6px; }}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit, QTextBrowser {{
    background: {c['input']}; color: {c['text']}; border: 1px solid {c['border_hi']};
    border-radius: 0; padding: 4px 6px; selection-background-color: {c['sel']}; }}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {c['accent']}; }}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
    color: {c['faint']}; background: {c['panel2']}; border-color: {c['border']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {c['panel']}; border: 1px solid {c['border_hi']};
                               selection-background-color: {c['sel']}; }}
QCheckBox, QRadioButton {{ background: transparent; spacing: 6px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 13px; height: 13px;
    border: 1px solid {c['border_hi']}; background: {c['input']}; border-radius: 0; }}
QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; }}
QRadioButton::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; }}
QTableView::indicator {{ width: 13px; height: 13px; border: 1px solid {c['border_hi']};
    background: {c['input']}; border-radius: 0; }}
QTableView::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; }}
QTableView::indicator:hover {{ border-color: {c['accent']}; }}
QGroupBox {{ border: 1px solid {c['border']}; margin-top: 14px; padding: 10px 8px 8px 8px;
            background: {c['panel']}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; color: {c['muted']};
                   font-weight: 600; background: {c['bg']}; }}

QTabWidget::pane {{ border: 1px solid {c['border']}; top: -1px; background: {c['panel']}; }}
QTabBar::tab {{ background: {c['panel2']}; color: {c['muted']}; border: 1px solid {c['border']};
               padding: 6px 14px; margin-right: -1px; border-radius: 0; }}
QTabBar::tab:selected {{ background: {c['panel']}; color: {c['text']};
                        border-top: 2px solid {c['accent']}; border-bottom-color: {c['panel']}; }}
QTabBar::tab:hover {{ color: {c['text']}; }}

QTreeView, QTableView, QListView, QListWidget, QTreeWidget {{
    background: {c['panel']}; alternate-background-color: {c['panel2']};
    border: 1px solid {c['border']}; gridline-color: {c['border']};
    selection-background-color: {c['sel']}; selection-color: {c['text']}; }}
QHeaderView::section {{ background: {c['panel3']}; color: {c['muted']}; border: none;
    border-right: 1px solid {c['border']}; border-bottom: 1px solid {c['border']};
    padding: 5px 6px; font-weight: 600; }}
QTableCornerButton::section {{ background: {c['panel3']}; border: none; }}

QProgressBar {{ background: {c['input']}; border: 1px solid {c['border_hi']}; border-radius: 0;
               text-align: center; color: {c['text']}; height: 16px; }}
QProgressBar::chunk {{ background: {c['accent']}; }}
QScrollBar:vertical {{ background: {c['panel']}; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c['border_hi']}; min-height: 24px; }}
QScrollBar:horizontal {{ background: {c['panel']}; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {c['border_hi']}; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QDockWidget {{ titlebar-close-icon: none; }}
QDockWidget::title {{ background: {c['panel3']}; padding: 5px 8px; border-bottom: 1px solid {c['border']}; }}
QSplitter::handle {{ background: {c['border']}; }}
QDialog {{ background: {c['bg']}; }}
"""
