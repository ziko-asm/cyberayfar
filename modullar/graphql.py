"""
MODUL: GraphQL INTROSPECTION
============================
GraphQL uc nöqtəsində "introspection" açıqdırsa, hücumçu bütün API
sxemini (bütün sorğu/mutation-ları) görə bilər — hücum səthini açır.
Zərərsiz: yalnız introspection sorğusu göndərir.
"""

import json
from core import http_client

UCLAR = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql",
         "/graphql/console", "/api/gql"]
SORGU = {"query": "{__schema{queryType{name} types{name}}}"}


def yoxla(bas_url, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    for yol in UCLAR:
        url = bas + yol
        cavab = http_client.al(
            url, metod="POST", timeout=timeout,
            data=json.dumps(SORGU),
            headers={"Content-Type": "application/json"},
        )
        if not cavab or cavab.status_code != 200:
            continue
        metn = cavab.text or ""
        if "__schema" in metn and '"types"' in metn and '"name"' in metn:
            hesabat.elave_et("orta", "graphql_introspection", url)
            return
