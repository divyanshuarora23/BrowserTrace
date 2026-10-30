# PyInstaller spec for a single-file browsertrace.exe.
# Build (on Windows, inside the project venv):
#   pip install pyinstaller
#   pyinstaller browsertrace.spec
# Output: dist/browsertrace.exe
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

src = Path("src/browsertrace")

datas = [
    (str(src / "api" / "static"), "browsertrace/api/static"),
    (str(src / "analysis" / "rules"), "browsertrace/analysis/rules"),
    ("docs/LIMITATIONS.md", "docs"),
]
datas += collect_data_files("tzdata")
datas += collect_data_files("reportlab")

hiddenimports = collect_submodules("browsertrace") + collect_submodules("uvicorn")

a = Analysis(
    ["tools/pyinstaller_entry.py"],
    pathex=["src"],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="browsertrace",
    console=True,
    upx=False,
)
