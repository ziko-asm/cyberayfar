"""
MODUL: DƏRİN TLS/SSL ANALİZİ
============================
Saytın şifrələmə qatını yoxlayır:
  • Sertifikat nə vaxt bitir? (az qalıbsa risk)
  • Self-signed (özü imzalı) sertifikatmı?
  • Köhnə/zəif protokol (TLS 1.0 / 1.1) dəstəklənirmi?
  • Hansı protokol danışıqla seçilir?
Zərərsiz: yalnız TLS əl-sıxışması (handshake), heç bir hücum yoxdur.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def _host_port(bas_url):
    p = urlparse(bas_url if "://" in bas_url else "https://" + bas_url)
    if p.scheme != "https":
        return None, None
    return p.hostname, p.port or 443


def _sertifikat(host, port):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert(), ss.version(), ss.cipher()
    except ssl.SSLCertVerificationError:
        return "DOGRULANMADI", None, None
    except Exception:
        return None, None, None


def _kohne_protokol_var(host, port):
    """TLS 1.0 / 1.1 dəstəklənirmi? (mümkünsə yoxlayır)"""
    kohneler = []
    for ad, maks in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                     ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = maks
            ctx.maximum_version = maks
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    kohneler.append(ad)
        except Exception:
            pass  # dəstəklənmir və ya klient bu versiyanı təklif edə bilmir
    return kohneler


def yoxla(bas_url, hesabat, timeout=8):
    host, port = _host_port(bas_url)
    if not host:
        return
    cert, versiya, cipher = _sertifikat(host, port)

    if cert == "DOGRULANMADI":
        hesabat.elave_et("yuksek", "tls_self", host)
        return
    if cert is None:
        return  # qoşulma alınmadı

    # Sertifikat bitmə tarixi
    bitir = cert.get("notAfter")
    if bitir:
        try:
            son = datetime.strptime(bitir, "%b %d %H:%M:%S %Y %Z")
            qalan = (son - datetime.utcnow()).days
            if qalan < 0:
                hesabat.elave_et("kritik", "tls_sertifikat", host, gun="bitib")
            elif qalan < 14:
                hesabat.elave_et("yuksek", "tls_sertifikat", host, gun=str(qalan))
        except Exception:
            pass

    # Köhnə protokollar
    kohneler = _kohne_protokol_var(host, port)
    if kohneler:
        hesabat.elave_et("yuksek", "tls_kohne", host, versiyalar=", ".join(kohneler))
