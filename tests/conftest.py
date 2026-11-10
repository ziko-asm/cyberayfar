import os
import sys

# Canlı rejim: icazə qapısı, sürət limiti və HSTS aktiv olsun
os.environ["PROD"] = "1"
os.environ.pop("SKAN_LIMIT", None)

KOK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (KOK, os.path.join(KOK, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)
