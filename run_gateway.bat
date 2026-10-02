@echo off
chcp 65001 >nul
title LongCat Sentinel v2.3 Enterprise Gateway

echo ===================================================
echo [LongCat Sentinel v2.3] 正在启动企业级熔断网关...
echo ===================================================

if "%SENTINEL_GATEWAY_TOKEN%"=="" (
    set SENTINEL_GATEWAY_TOKEN=sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a
)

if "%SENTINEL_ADMIN_TOKEN%"=="" (
    set SENTINEL_ADMIN_TOKEN=adm-sentinel-99e8d7c6b5a4
)

if "%LONGCAT_API_KEY%"=="" (
    set LONGCAT_API_KEY=sk-meituan-longcat-demo-key
)

python main.py
pause
