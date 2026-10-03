# ==============================================================================
# LongCat Sentinel - Main Entrypoint & CLI Runner
# ==============================================================================
import uvicorn
import sys
import os
import webbrowser
import threading
import time
import secrets
from pathlib import Path
from dotenv import load_dotenv

# 1. 确定运行环境与工作目录（支持 PyInstaller 单文件打包与源码直跑）
if getattr(sys, "frozen", False):
    exe_dir = Path(sys.executable).parent
    os.chdir(str(exe_dir))
    env_path = exe_dir / ".env"
else:
    exe_dir = Path(__file__).resolve().parent
    env_path = exe_dir / ".env"


def ensure_environment():
    """首次运行自愈：若缺失 .env 则自动创建高强度网关凭证并引导配置 API Key"""
    if not env_path.exists():
        token = f"sk-ant-sentinel-gw-{secrets.token_urlsafe(32)}"
        default_env = (
            "# ==============================================================================\n"
            "# LongCat Sentinel 配置文件\n"
            "# ==============================================================================\n\n"
            "# 1. 美团 LongCat 官方真实 API Key（必填，请向开放平台申请后填入）\n"
            'LONGCAT_API_KEY=""\n\n'
            "# 2. 本地客户端鉴权令牌（已为您自动生成高强度随机安全凭据）\n"
            f'SENTINEL_GATEWAY_TOKEN="{token}"\n\n'
            "# 3. Web 管理控制台口令（可选，留空即为默认免密本地管理模式）\n"
            'SENTINEL_ADMIN_TOKEN=""\n'
        )
        try:
            env_path.write_text(default_env, encoding="utf-8")
        except Exception:
            pass

    load_dotenv(dotenv_path=env_path)

    # 确保本地客户端通信网关 Token 必须存在且有效
    gw_token = (os.getenv("SENTINEL_GATEWAY_TOKEN") or "").strip()
    if not gw_token or len(gw_token) < 16:
        new_token = f"sk-ant-sentinel-gw-{secrets.token_urlsafe(32)}"
        os.environ["SENTINEL_GATEWAY_TOKEN"] = new_token
        try:
            content = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
            if "SENTINEL_GATEWAY_TOKEN=" in content:
                lines = [
                    f'SENTINEL_GATEWAY_TOKEN="{new_token}"' if l.strip().startswith("SENTINEL_GATEWAY_TOKEN=") else l
                    for l in content.splitlines()
                ]
                env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            else:
                with open(env_path, "a", encoding="utf-8") as f:
                    f.write(f'\nSENTINEL_GATEWAY_TOKEN="{new_token}"\n')
        except Exception:
            pass

    # 检查美团官方 API Key
    api_key = (os.getenv("LONGCAT_API_KEY") or "").strip()
    if not api_key:
        print("=" * 70)
        print(" [LongCat Sentinel] 欢迎使用美团大模型抗死循环与智能熔断网关！")
        print("=" * 70)
        print("\n [提示] 检测到当前尚未配置美团官方 API Key (LONGCAT_API_KEY)。\n")
        print(" 您可以直接在此粘贴您的美团 API Key (例如 ak_xxx... 或 sk-meituan-xxx...):")
        try:
            user_input = input(" >> API Key: ").strip().strip('"').strip("'")
        except (EOFError, KeyboardInterrupt):
            user_input = ""

        if user_input:
            os.environ["LONGCAT_API_KEY"] = user_input
            try:
                content = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
                if "LONGCAT_API_KEY=" in content:
                    lines = [
                        f'LONGCAT_API_KEY="{user_input}"' if l.strip().startswith("LONGCAT_API_KEY=") else l
                        for l in content.splitlines()
                    ]
                    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                else:
                    with open(env_path, "a", encoding="utf-8") as f:
                        f.write(f'\nLONGCAT_API_KEY="{user_input}"\n')
                print("\n [OK] API Key 已成功保存至 .env，正在启动网关服务...\n")
            except Exception as e:
                print(f" [WARN] 写入配置文件失败: {e}，将在当前进程临时生效。\n")
        else:
            print("\n [错误] 未提供有效的 LONGCAT_API_KEY，网关无法转发至上游集群。")
            print(f" 请用记事本打开目录下的配置文件：\n  --> {env_path.resolve()}\n")
            print(" 在第一行填入您的真实美团 API Key 后，重新双击启动即可。\n")
            try:
                input(" 请按回车键退出程序...")
            except Exception:
                pass
            sys.exit(1)


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
    ensure_environment()

    try:
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
    except Exception as e:
        print("\n" + "=" * 70)
        print(f" [致命异常] 网关启动失败: {e}")
        print("=" * 70)
        import traceback
        traceback.print_exc()
        print("\n程序异常退出，按回车键关闭窗口...")
        try:
            input()
        except Exception:
            pass
        sys.exit(1)
