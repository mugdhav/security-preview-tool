"""Tests for the security-preview desktop launcher (``security_preview.desktop``)."""
from __future__ import annotations

import socket
import threading

from security_preview import desktop


def test_free_port_is_bindable():
    port = desktop._free_port()
    assert 1024 < port < 65536
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))  # still free right after the probe


def test_build_url_plain():
    assert desktop._build_url(8765, None) == "http://127.0.0.1:8765/"


def test_build_url_with_scan_deep_link():
    url = desktop._build_url(8765, "/home/me/proj")
    assert url.startswith("http://127.0.0.1:8765/?")
    assert "path=%2Fhome%2Fme%2Fproj" in url
    assert "autoscan=1" in url


def test_wait_healthz_times_out_fast():
    # Nothing is listening on this port -> returns False without hanging.
    port = desktop._free_port()
    assert desktop._wait_healthz(port, timeout=0.5) is False


def test_wait_healthz_succeeds_against_real_app():
    import uvicorn

    from security_preview.server.app import create_app

    port = desktop._free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error")
    )
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        assert desktop._wait_healthz(port, timeout=10) is True
    finally:
        server.should_exit = True
        t.join(timeout=5)


def test_main_falls_back_to_browser_when_pywebview_absent(monkeypatch):
    """No pywebview installed -> open the system browser, serve, exit cleanly."""
    monkeypatch.setitem(__import__("sys").modules, "webview", None)

    opened: list = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))

    real_run_server = desktop._run_server
    captured: dict = {}

    def fake_run_server(app, port):
        server, thread = real_run_server(app, port)
        captured["server"] = server
        captured["thread"] = thread
        return server, thread

    monkeypatch.setattr(desktop, "_run_server", fake_run_server)

    # Make thread.join() return immediately instead of blocking on the server.
    monkeypatch.setattr(threading.Thread, "join", lambda self, timeout=None: None)

    rc = desktop.main(["--no-window"])
    assert rc == 0
    assert opened and opened[0].startswith("http://127.0.0.1:")
    captured["server"].should_exit = True
