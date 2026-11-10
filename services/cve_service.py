import json
import os
import requests
from config import NOME_ARQUIVO_CVES
from utils import traduzir_texto, validar_cve


def carregar_cves_locais():
    """Carrega o cache local de CVEs já pesquisadas."""
    if not os.path.exists(NOME_ARQUIVO_CVES):
        return {}
    try:
        with open(NOME_ARQUIVO_CVES, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def guardar_cve_local(codigo_cve, dados_cve):
    """Salva os dados de uma CVE no cache local para pesquisas futuras sem gastar requisições."""
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
    """Traduz a pontuação CVSS numérica em rótulo visual, cor e recomendação de mitigação."""
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
    """Consulta os detalhes de uma CVE via validação local, cache ou API do NIST/NVD."""
    codigo_limpo = codigo_cve.strip().upper()

    # 1. Validação Prévia 🔍
    if not validar_cve(codigo_limpo):
        return {
            "erro": "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)"
        }

    # 2. Busca no Cache Local 💾
    cves_locais = carregar_cves_locais()
    if codigo_limpo in cves_locais:
        dados_cache = cves_locais[codigo_limpo].copy()
        dados_cache["origem"] = "local"
        return dados_cache

    # 3. Consulta à API da NVD 🌐
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={codigo_limpo}"
    headers = {"User-Agent": "MeuAppPython/1.0"}

    try:
        resposta = requests.get(url, headers=headers, timeout=10)
        if resposta.status_code == 200:
            dados = resposta.json()
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

            # 4. Tradução Automática para Português 🔤
            descricao_pt = traduzir_texto(descricao_en)

            estrutura_cve = {
                "id": codigo_limpo,
                "cvss": cvss_score,
                "descricao_en": descricao_en,
                "descricao": descricao_pt,
                "origem": "api",
            }

            # 5. Guarda no Cache Local para futuras pesquisas 💾
            guardar_cve_local(codigo_limpo, estrutura_cve)

            return estrutura_cve
        else:
            return {
                "erro": f"Erro na resposta da NVD. Código HTTP: {resposta.status_code}"
            }
    except Exception as e:
        return {"erro": f"Falha na conexão com a NVD: {e}"}
