import json
import os
from config import NOME_ARQUIVO_CVES
from utils import validar_cve

try:
    import requests
    TEM_REQUESTS = True
except ImportError:
    requests = None
    TEM_REQUESTS = False
    import urllib.request
    import urllib.error

def carregar_cves_locais():
    if not os.path.exists(NOME_ARQUIVO_CVES):
        return {}
    try:
        with open(NOME_ARQUIVO_CVES, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}

def guardar_cve_local(codigo_cve, dados_cve):
    dados_locais = carregar_cves_locais()
    dados_locais[codigo_cve] = dados_cve
    try:
        with open(NOME_ARQUIVO_CVES, "w", encoding="utf-8") as f:
            json.dump(dados_locais, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar cache da CVE: {e}")
        return False

def traduzir_severidade(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return (
                "🚨 CRÍTICO (Ação Urgente!)",
                "#ef4444",
                "💡 Ação Recomendada: Aplicar patch de segurança IMEDIATAMENTE e isolar o ativo se possível.",
            )
        elif score >= 7.0:
            return (
                "⚠️ ALTO (Atenção Prioritária)",
                "#f97316",
                "💡 Ação Recomendada: Agendar atualização do software o quanto antes.",
            )
        elif score >= 4.0:
            return (
                "🟡 MÉDIO (Planejar Correção)",
                "#eab308",
                "💡 Ação Recomendada: Corrigir na próxima janela de manutenção programada.",
            )
        else:
            return (
                "🟢 BAIXO (Risco Reduzido)",
                "#10b981",
                "💡 Ação Recomendada: Monitorar o ativo; correção opcional.",
            )
    except (ValueError, TypeError):
        return (
            "❓ Desconhecido / Não Avaliado",
            "#94a3b8",
            "💡 Ação Recomendada: Consultar a documentação do fornecedor do software.",
        )

def consultar_cve_nvd(codigo_cve):
    codigo_limpo = codigo_cve.strip().upper()

    if not validar_cve(codigo_limpo):
        return {
            "erro": "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)"
        }

    cves_locais = carregar_cves_locais()
    if codigo_limpo in cves_locais:
        dados_cache = cves_locais[codigo_limpo].copy()
        dados_cache["origem"] = "local"
        return dados_cache

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={codigo_limpo}"
    headers = {"User-Agent": "MeuAppPython/1.0"}

    try:
        dados = None
        if TEM_REQUESTS:
            resposta = requests.get(url, headers=headers, timeout=10)
            if resposta.status_code == 200:
                dados = resposta.json()
            else:
                return {"erro": f"Erro na resposta da NVD. Código HTTP: {resposta.status_code}"}
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    corpo = resp.read().decode("utf-8")
                    dados = json.loads(corpo)
                else:
                    return {"erro": f"Erro na resposta da NVD. Código HTTP: {resp.status}"}

        if not dados:
            return {"erro": "Resposta vazia da NVD."}

        vulnerabilidades = dados.get("vulnerabilities", [])
        if not vulnerabilidades:
            return {
                "erro": "Vulnerabilidade não encontrada na base de dados oficial da NVD."
            }

        cve_data = vulnerabilidades[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        descricao_en = "Descrição não disponível."
        for d in descriptions:
            if d.get("lang") == "en":
                descricao_en = d.get("value")
                break

        metrics = cve_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [])
        cvss_score = (
            cvss_data[0].get("cvssData", {}).get("baseScore", "N/A")
            if cvss_data
            else "N/A"
        )

        estrutura_cve = {
            "id": codigo_limpo,
            "cvss": cvss_score,
            "descricao_en": descricao_en,
            "descricao": descricao_en,
            "origem": "api",
        }

        guardar_cve_local(codigo_limpo, estrutura_cve)
        return estrutura_cve

    except Exception as e:
        return {"erro": f"Falha na conexão com a NVD: {e}"}
