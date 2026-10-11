@echo off
chcp 65001 >nul
title LongCat Sentinel 龙猫熔断哨兵
cd /d "%~dp0"
echo.
echo ======================================================================
echo    LongCat Sentinel - 正在以源码模式极速启动独立原生桌面窗口...
echo ======================================================================
echo.
python main.py
if errorlevel 1 (
    echo.
    echo [提示] 程序已退出。如果有报错，请查看上方输出。按任意键关闭窗口...
    pause >nul
)
