import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from config import NOME_ARQUIVO_AUDITORIA

_AUDIT_LOCK = threading.RLock()


def _limpar_campo_log(valor: Any, max_len: int = 200) -> str:
    texto = str(valor if valor is not None else "")
    return texto.replace("\r", " ").replace("\n", " ").strip()[:max_len]


def registrar_evento(
    acao: str,
    usuario: str = "anonimo",
    ip: str = "unknown",
    recurso: str = "",
    detalhes: Optional[Dict[str, Any]] = None,
    sucesso: bool = True,
) -> Dict[str, Any]:
    evento: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "acao": _limpar_campo_log(acao, max_len=64),
        "usuario": _limpar_campo_log(usuario or "anonimo", max_len=64),
        "ip": _limpar_campo_log(ip or "unknown", max_len=64),
        "recurso": _limpar_campo_log(recurso, max_len=128),
        "sucesso": bool(sucesso),
    }
    if detalhes:
        evento["detalhes"] = {
            _limpar_campo_log(k, max_len=64): _limpar_campo_log(v, max_len=200)
            for k, v in detalhes.items()
        }

    linha = json.dumps(evento, ensure_ascii=False)
    logging.info(
        "[AUDIT] acao=%s usuario=%s ip=%s recurso=%s sucesso=%s",
        evento["acao"],
        evento["usuario"],
        evento["ip"],
        evento["recurso"],
        evento["sucesso"],
    )

    with _AUDIT_LOCK:
        try:
            diretorio = os.path.dirname(os.path.abspath(NOME_ARQUIVO_AUDITORIA))
            os.makedirs(diretorio, exist_ok=True)
            with open(NOME_ARQUIVO_AUDITORIA, "a", encoding="utf-8") as f:
                f.write(linha + "\n")
        except OSError as e:
            logging.error("⚠️ Falha ao gravar log de auditoria: %s", e)

    return evento


def listar_eventos(limite: int = 50) -> List[Dict[str, Any]]:
    try:
        max_itens = max(1, min(int(limite), 200))
    except (TypeError, ValueError):
        max_itens = 50

    with _AUDIT_LOCK:
        if not os.path.exists(NOME_ARQUIVO_AUDITORIA):
            return []
        try:
            with open(NOME_ARQUIVO_AUDITORIA, "r", encoding="utf-8") as f:
                linhas = f.readlines()
        except OSError:
            return []

    eventos: List[Dict[str, Any]] = []
    for linha in reversed(linhas):
        linha = linha.strip()
        if not linha:
            continue
        try:
            item = json.loads(linha)
            if isinstance(item, dict):
                eventos.append(item)
        except json.JSONDecodeError:
            continue
        if len(eventos) >= max_itens:
            break
    return eventos
