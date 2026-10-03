# ==============================================================================
# LongCat Sentinel - Main Entrypoint & CLI Runner
# ==============================================================================
import uvicorn
import sys
import os
import webbrowser
import threading
import time
from pathlib import Path
from dotenv import load_dotenv

# 支持 PyInstaller 打包环境下的工作目录矫正与 .env 探测
if getattr(sys, "frozen", False):
    exe_dir = Path(sys.executable).parent
    os.chdir(str(exe_dir))
    load_dotenv(dotenv_path=exe_dir / ".env")
else:
    load_dotenv()

from rich.console import Console
from rich.table import Table

console = Console()

def print_banner(host: str, port: int, scheme: str = "http"):
    banner = f"""[bold yellow]
   __                                    _     ____             _   _            _ 
  / /   ___  _ __   __ _  ___  __ _  ___| |_  / ___|  ___ _ __ | |_(_)_ __   ___| |
 / /   / _ \\| '_ \\ / _` |/ __|/ _` |/ __| __| \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |
/ /___| (_) | | | | (_| | (__| (_| | (__| |_   ___) |  __/ | | | |_| | | | |  __/ |
\\____/ \\___/|_| |_|\\__, |\\___|\\__,_|\\___|\\__| |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|
                   |___/                                                           
[/bold yellow]
[bold green]LongCat Sentinel v2.3 Enterprise Final Hardened Edition[/bold green]
[dim]美团 LongCat 2.5 官方级抗循环与双轨智能熔断网关[/dim]
"""
    console.print(banner)

    table = Table(title="服务接入点矩阵 (Active Endpoints)", style="yellow")
    table.add_column("协议 / 客户端", style="cyan")
    table.add_column("本地接入地址", style="green")
    table.add_column("状态", style="bold green")

    table.add_row("Claude Code (Anthropic)", f"{scheme}://{host}:{port}/v1/messages", "● READY")
    table.add_row("Hermes / Cursor (OpenAI)", f"{scheme}://{host}:{port}/v1/chat/completions", "● READY")
    table.add_row("Web 监控仪表盘", f"{scheme}://{host}:{port}/dashboard", "● ONLINE")
    table.add_row("健康检查接口", f"{scheme}://{host}:{port}/health", "● PASS")

    console.print(table)
    console.print(f"[bold cyan]网关已就绪！监听地址: {scheme}://{host}:{port}[/bold cyan]\n")


def open_browser_tab(url: str):
    time.sleep(1.2)
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    from longcat_sentinel.server import app, config

    server_cfg = config.server
    host = server_cfg.host or "127.0.0.1"
    port = int(server_cfg.port) if server_cfg.port is not None else 8080
    scheme = "https" if server_cfg.tls_enabled else "http"

    print_banner(host, port, scheme)

    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    # 启动 1 秒后自动弹出默认浏览器展示监控大屏
    threading.Thread(
        target=open_browser_tab,
        args=(f"{scheme}://{display_host}:{port}/dashboard",),
        daemon=True,
    ).start()

    ssl_kwargs = {}
    if server_cfg.tls_enabled:
        if server_cfg.tls_cert_path:
            ssl_kwargs["ssl_certfile"] = server_cfg.tls_cert_path
        if server_cfg.tls_key_path:
            ssl_kwargs["ssl_keyfile"] = server_cfg.tls_key_path

    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=server_cfg.workers or 1,
        log_level="info",
        **ssl_kwargs,
    )
