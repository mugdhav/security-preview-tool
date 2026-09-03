"""Desktop launcher for Vulnascan (the security-preview engine).

Turns ``security-preview serve`` into a zero-config, double-click app: pick a
free ``127.0.0.1`` port, run the FastAPI app on a daemon thread, wait for
``/healthz`` to answer, then open a native window (pywebview: WebView2 on
Windows, WKWebView on macOS, WebKitGTK on Linux). Closing the window shuts the
server down and the process exits.

If pywebview is not installed (headless / server install), it falls back to
opening the system browser and blocking on the server, so ``serve`` keeps
working with no extra dependency.

Entry points:
    vulnascan-desktop / security-preview-desktop   console script
    security-preview serve --desktop               delegates here (handy for dev)
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_HEALTHZ_TIMEOUT = 10.0
_WINDOW_TITLE = "Vulnascan"
_WINDOW_SIZE = (1100, 760)
_WINDOW_MIN_SIZE = (900, 600)

__all__ = ["main"]


def _free_port() -> int:
    """Ask the OS for an unused 127.0.0.1 TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_healthz(port: int, timeout: float = _HEALTHZ_TIMEOUT) -> bool:
    """Poll ``GET /healthz`` until it answers or ``timeout`` elapses."""
    url = f"http://127.0.0.1:{port}/healthz"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    return False


def _build_url(port: int, scan_path: str | None) -> str:
    url = f"http://127.0.0.1:{port}/"
    if scan_path:
        query = urllib.parse.urlencode({"path": scan_path, "autoscan": "1"})
        url = f"{url}?{query}"
    return url


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnascan-desktop",
        description="Open the Vulnascan desktop window.",
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        default=None,
        help="pre-fill this folder and start scanning as soon as the window opens",
    )
    parser.add_argument(
        "--no-window",
        action="store_true",
        help="skip pywebview even if installed; use the system browser",
    )
    return parser.parse_args(argv)


def _run_server(app, port: int):
    """Start uvicorn on a daemon thread; return (server, thread)."""
    import uvicorn

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="security-preview-server", daemon=True)
    thread.start()
    return server, thread


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        import webview  # type: ignore
    except ImportError:
        webview = None

    from .server.app import create_app

    port = _free_port()

    # The window handle is only known after webview.create_window(); the picker
    # closure reads it lazily so /api/pick-folder can be wired before the window
    # exists.
    holder: dict = {}

    def folder_picker() -> str | None:
        window = holder.get("window")
        if window is None or webview is None:
            return None
        result = window.create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return None
        return result[0] if isinstance(result, (list, tuple)) else str(result)

    app = create_app(mode="desktop", folder_picker=folder_picker)
    server, thread = _run_server(app, port)

    if not _wait_healthz(port):
        print("security-preview: server did not become healthy in time", file=sys.stderr)
        server.should_exit = True
        thread.join(timeout=5)
        return 1

    url = _build_url(port, args.scan)

    if webview is None or args.no_window:
        import webbrowser

        print(f"security-preview listening on {url}  (Ctrl+C to stop)")
        webbrowser.open(url)
        try:
            thread.join()
        except KeyboardInterrupt:
            pass
        server.should_exit = True
        thread.join(timeout=5)
        return 0

    holder["window"] = webview.create_window(
        _WINDOW_TITLE,
        url,
        width=_WINDOW_SIZE[0],
        height=_WINDOW_SIZE[1],
        min_size=_WINDOW_MIN_SIZE,
    )
    webview.start()

    # Window closed -> tear the server down and exit.
    server.should_exit = True
    thread.join(timeout=5)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
