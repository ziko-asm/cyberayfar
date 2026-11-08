# Vercel giriş nöqtəsi — Flask app-ı yükləyir.
# Vercel bütün sorğuları bura yönləndirir (bax: vercel.json).
import os
import sys

# Kök qovluğu import yoluna əlavə et (core, modullar, app görünsün)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402  (Vercel bu `app` obyektini işlədir)
