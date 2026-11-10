import re

try:
    from deep_translator import GoogleTranslator
except ImportError:
    GoogleTranslator = None


def sanitizar_texto(texto):
    """Remove caracteres especiais perigosos de strings."""
    if not texto:
        return ""
    return re.sub(r'[<>\'\"\\\\;]', "", str(texto)).strip()


def validar_cve(cve_texto):
    """Valida se a string atende ao padrão oficial de CVE (ex: CVE-2021-44228)."""
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", cve_texto.strip().upper()))


def validar_hostname(hostname):
    """Valida se o hostname possui formato válido e tamanho máximo de 63 caracteres."""
    return bool(
        hostname
        and len(hostname) <= 63
        and re.match(r"^[a-zA-Z0-9.-]+$", hostname)
    )


def validar_id(id_str):
    """Valida se o ID é um número inteiro válido entre 1 e 999999."""
    if not id_str.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(id_str)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser entre 1 e 999999!"
    return True, val


def traduzir_texto(texto_ingles):
    """Traduz texto de inglês para português usando deep_translator (se disponível)."""
    if not texto_ingles:
        return "Descrição não disponível."
    if GoogleTranslator is None:
        return texto_ingles
    try:
        return GoogleTranslator(source="en", target="pt").translate(texto_ingles)
    except Exception:
        return texto_ingles
