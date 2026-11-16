import re

try:
    from deep_translator import GoogleTranslator
except ImportError:
    GoogleTranslator = None

def sanitizar_texto(texto):
    if not texto:
        return ""
    return re.sub(r'[<>\'\"\\\\;]', "", str(texto)).strip()

def validar_cve(cve_texto):
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", cve_texto.strip().upper()))

def validar_hostname(hostname):
    return bool(
        hostname
        and len(hostname) <= 63
        and re.match(r"^[a-zA-Z0-9.-]+$", hostname)
    )

def validar_id(id_str):
    if not id_str.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(id_str)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser entre 1 e 999999!"
    return True, val

def traduzir_texto(texto_ingles):
    if not texto_ingles:
        return "Descrição não disponível."
    if GoogleTranslator is None:
        return texto_ingles
    try:
        return GoogleTranslator(source="en", target="pt").translate(texto_ingles)
    except Exception:
        return texto_ingles
