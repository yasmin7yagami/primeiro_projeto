import re
from typing import Tuple, Union

def sanitizar_texto(texto, max_len: int = 200) -> str:
    if texto is None:
        return ""
    limpo = re.sub(r"[\x00-\x1f\x7f]", "", str(texto))
    limpo = re.sub(r'[<>\'\"\\\\;]', "", limpo).strip()
    return limpo[:max_len]

def validar_cve(cve_texto) -> bool:
    if not isinstance(cve_texto, str):
        return False
    return bool(re.match(r"^CVE-\d{4}-\d{4,7}$", cve_texto.strip().upper()))

def validar_hostname(hostname) -> bool:
    if not isinstance(hostname, str):
        return False
    host = hostname.strip()
    return bool(
        host
        and len(host) <= 63
        and re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?$", host)
    )

def normalizar_hostname(hostname: str) -> str:
    return str(hostname or "").strip().lower()

def validar_id(id_str) -> Tuple[bool, Union[int, str]]:
    texto = str(id_str).strip() if id_str is not None else ""
    if not texto.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(texto)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser entre 1 e 999999!"
    return True, val

def validar_login(login) -> Tuple[bool, str]:
    if not isinstance(login, str):
        return False, "Login inválido."
    login_norm = login.strip().lower()
    if len(login_norm) < 3 or len(login_norm) > 32:
        return False, "O login deve ter entre 3 e 32 caracteres."
    if not re.match(r"^[a-z0-9._-]+$", login_norm):
        return False, "O login deve conter apenas letras minúsculas, números, '.', '_' ou '-'."
    return True, login_norm

def validar_senha_forte(senha) -> Tuple[bool, str]:
    if not isinstance(senha, str):
        return False, "Senha inválida."
    if len(senha) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres."
    if len(senha) > 128:
        return False, "A senha deve ter no máximo 128 caracteres."
    if not re.search(r"[A-Za-z]", senha) or not re.search(r"\d", senha):
        return False, "A senha deve conter pelo menos uma letra e um número."
    return True, ""
