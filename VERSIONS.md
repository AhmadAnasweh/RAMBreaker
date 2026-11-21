# VERSIONS (checked against GitHub on 2026-11-07)

| Component | Version | Commit/tag | Location |
|---|---|---|---|
| Volatility 3 | 2.28.2 (latest release, 2026-09-17) | tag v2.28.2 = 881e970121c16f0932fb9d16fbd5fb258cbcbf75 | runtime\volatility3 (editable in runtime\py3) |
| Volatility 2 | 2.6.1 (latest; repo archived) | master 328a178e (2025-05-16, newest commit) | runtime\volatility2 |
| Python 3 | 3.13.17 | python.org via winget | venv runtime\py3 |
| Python 2.7 | 2.7.18 amd64 (MD5 a425c758d38f8e28b56f4724b499239a) | msiexec /a extract | runtime\py27 |
| Vol2 deps | distorm3 3.3.8 (ctypes DLL, from win-amd64 installer), pycryptodome 3.21.0, yara-python 3.11.0, openpyxl 2.6.4, pytz, pillow | cp27 win_amd64 wheels | runtime\py27 |
| Vol3 deps | volatility3[full] extras (yara-python, capstone, pefile, pycryptodome, ...) | pip | runtime\py3 |
| numpy | 2.5.4 (added 2026-11-08: required by btf2isf; was missing from the portable runtime) | pip | runtime\py3 |
| btf2isf (in-dump BTF -> ISF) | 0.2 (2026-11-08: synthesizes the anonymous tk_core type) | src\modules\btf2isf.py | app\modules |
| Vol3 symbol packs | windows.zip (2019-10-16), linux.zip (2024-11-08), mac.zip (2020-06-22) | downloads.volatilityfoundation.org | runtime\symbols |
| Upstream RAMBreaker | v6.2 | fb467f3 | src\ |
