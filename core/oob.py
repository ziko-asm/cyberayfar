"""
OOB (Out-of-Band) COLLABORATOR
==============================
Blind (kor) zəiflikləri tutmaq üçün. Hədəf serverimizə geri sorğu
("callback") edirsə, deməli zəiflik təsdiqlənir:
  • Blind SSRF  — server callback URL-i çəkir
  • Blind RCE   — server "curl callback" əmrini işlədir
  • Blind XXE   — XML parser callback-ı çəkir

Öz serverimiz (cyberayfar.onrender.com/oob/<token>) collaborator kimi
işləyir — ayrıca domen/DNS lazım deyil. Hitlər yaddaşda saxlanılır
(tək-worker serverdə işləyir; Vercel-də efemer olduğu üçün söndürülür).
"""

import time
import secrets
import threading

_hitler = {}      # token -> [hit...]
_lock = threading.Lock()


def yeni_token():
    return secrets.token_hex(8)


def qeyd_et(token, info):
    with _lock:
        _hitler.setdefault(token, []).append({**info, "vaxt": time.time()})


def vuruldu(token):
    with _lock:
        return len(_hitler.get(token, [])) > 0


def temizle(token):
    with _lock:
        _hitler.pop(token, None)
