# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('config.yaml', '.'), ('longcat_sentinel/web/dashboard.html', 'longcat_sentinel/web'), ('mmexport1790941560209.jpg', '.')],
    hiddenimports=[
        'uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto',
        'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespans', 'uvicorn.lifespans.on', 'rich', 'rapidfuzz',
        # Every internal subpackage is listed explicitly: they used to rely on
        # implicit namespace packages, which PyInstaller does not collect reliably.
        'longcat_sentinel.config', 'longcat_sentinel.auth', 'longcat_sentinel.metrics',
        'longcat_sentinel.server',
        'longcat_sentinel.breaker', 'longcat_sentinel.breaker.compliant_injector',
        'longcat_sentinel.detector', 'longcat_sentinel.detector.capability_manifest',
        'longcat_sentinel.detector.loop_scorer',
        'longcat_sentinel.detector.parallel_tool_tracker',
        'longcat_sentinel.detector.ring_buffer',
        'longcat_sentinel.detector.tool_loop_guard',
        'longcat_sentinel.parser', 'longcat_sentinel.parser.stream_fsm',
        'longcat_sentinel.router', 'longcat_sentinel.router.anthropic_router',
        'longcat_sentinel.router.openai_router',
        'longcat_sentinel.web', 'longcat_sentinel.web.admin_api',
        'longcat_sentinel.circuit_breaker',
        'longcat_sentinel.circuit_breaker.redactor',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='LongCatSentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app_icon.ico'],
)
