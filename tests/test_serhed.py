"""Skan sərhədi: hücum sorğuları yalnız təsdiqlənmiş hosta və açıq internetə gedir."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import authorization, http_client


class _Yonlendiren(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_port
        if self.path.startswith("/kenara"):          # başqa hosta (localhost) yönləndirir
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/son{self.path[7:]}")
        elif self.path.startswith("/iceri"):          # eyni hosta yönləndirir
            self.send_response(302)
            self.send_header("Location", "/son")
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Yonlendiren)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()


def test_basqa_hosta_redirect_izlenmir(server):
    http_client.hedef_qur(f"127.0.0.1:{server}", daxiliye_icaze=True)
    try:
        c = http_client.al(f"http://127.0.0.1:{server}/kenara?q=<script>")
        assert c is not None and c.status_code == 302      # yük localhost-a ÖTÜRÜLMƏDİ
        ici = http_client.al(f"http://127.0.0.1:{server}/iceri")
        assert ici.status_code == 200 and len(ici.history) == 1   # eyni host: izlənir
        assert http_client.al(f"http://localhost:{server}/") is None  # sərhəd xarici host
    finally:
        http_client.hedef_sil(f"127.0.0.1:{server}")


def test_canli_rejimde_daxili_ip_bloklanir(server):
    http_client.hedef_qur(f"127.0.0.1:{server}", daxiliye_icaze=False)
    try:
        assert http_client.al(f"http://127.0.0.1:{server}/") is None
    finally:
        http_client.hedef_sil(f"127.0.0.1:{server}")


def test_www_variantina_icaze_var():
    http_client.hedef_qur("menim.az")
    try:
        assert http_client.host_icazelidir("https://www.menim.az/a")
        assert http_client.host_icazelidir("https://MENIM.az/a")
        assert not http_client.host_icazelidir("https://qurban.az/a")
        assert not http_client.host_icazelidir("https://menim.az.qurban.az/a")
    finally:
        http_client.hedef_sil("menim.az")
    assert not http_client._aktiv_hostlar and not http_client._daxiliye_icaze


def test_sahiblik_fayli_yalniz_eyni_saytdan():
    assert authorization._eyni_sayt("https://www.menim.az/.well-known/x", "menim.az")
    assert authorization._eyni_sayt("https://menim.az/x", "www.menim.az")
    assert not authorization._eyni_sayt("https://pis.com/x", "menim.az")


def test_vercelde_saxta_xff_limiti_aldatmir(monkeypatch):
    import app as tetbiq
    monkeypatch.setenv("VERCEL", "1")
    with tetbiq.app.test_request_context("/", headers={
            "X-Forwarded-For": "1.2.3.4, 9.9.9.9",
            "x-vercel-forwarded-for": "9.9.9.9"}):
        assert tetbiq._musteri_ip() == "9.9.9.9"
