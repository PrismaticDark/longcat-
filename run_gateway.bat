@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
title LongCat Sentinel v2.3.1 Security Hardened Gateway

echo ===================================================
echo [LongCat Sentinel v2.3.1] 正在启动企业级熔断网关...
echo ===================================================

:: 凭证一律来自环境变量或 .env，脚本中不再内置任何默认口令。
:: 首次运行时自动生成一份高强度随机凭证模板。
if exist ".env" goto CHECK_TOKEN

echo [LongCat Sentinel] 未检测到 .env，正在生成高强度随机凭证模板...
python -c "import secrets, pathlib; token = secrets.token_urlsafe(32); pathlib.Path('.env').write_text(f'LONGCAT_API_KEY=\nSENTINEL_GATEWAY_TOKEN=\"sk-ant-sentinel-gw-{token}\"\n', encoding='utf-8')"
echo [LongCat Sentinel] 已生成 .env：请先编辑填入真实的美团 LONGCAT_API_KEY，然后重新运行本脚本。
echo.
pause
exit /b 2

:CHECK_TOKEN
if not defined SENTINEL_GATEWAY_TOKEN (
    echo [LongCat Sentinel] 提示：SENTINEL_GATEWAY_TOKEN 未在系统环境中显式设置，将读取 .env 中的配置。
)

python main.py
pause
