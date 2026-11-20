import hashlib
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from config import NOME_ARQUIVO_USUARIOS
from utils import sanitizar_texto, validar_login, validar_senha_forte

PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 100_000
ROLES_VALIDOS = {"admin", "user"}
SESSION_TTL_PADRAO = int(os.environ.get("SESSION_TTL_SECONDS", 28800))

_AUTH_LOCK = threading.RLock()


def gerar_hash_senha(senha: str, salt: Optional[str] = None, iteracoes: int = PBKDF2_ITERATIONS) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt.encode("utf-8"), iteracoes
    )
    return f"pbkdf2_sha256${iteracoes}${salt}${key.hex()}"


def _hash_e_legado(hash_salvo: str) -> bool:
    if not isinstance(hash_salvo, str):
        return False
    partes = hash_salvo.split("$")
    if len(partes) == 2:
        return True
    if len(partes) == 4 and partes[0] == "pbkdf2_sha256":
        try:
            return int(partes[1]) < PBKDF2_ITERATIONS
        except ValueError:
            return True
    return False


def verificar_senha(senha_digitada: str, hash_salvo: str) -> bool:
    if not isinstance(senha_digitada, str) or not isinstance(hash_salvo, str):
        return False
    try:
        partes = hash_salvo.split("$")
        if len(partes) == 4 and partes[0] == "pbkdf2_sha256":
            iteracoes = int(partes[1])
            salt = partes[2]
            key_hex = partes[3]
        elif len(partes) == 2:
            iteracoes = LEGACY_PBKDF2_ITERATIONS
            salt, key_hex = partes
        else:
            return False

        novo_hash = hashlib.pbkdf2_hmac(
            "sha256", senha_digitada.encode("utf-8"), salt.encode("utf-8"), iteracoes
        ).hex()
        return secrets.compare_digest(novo_hash, key_hex)
    except Exception:
        return False


def _salvar_arquivo_usuarios(usuarios: Dict[str, Any]) -> None:
    diretorio = os.path.dirname(os.path.abspath(NOME_ARQUIVO_USUARIOS))
    os.makedirs(diretorio, exist_ok=True)
    arquivo_temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=diretorio,
            prefix=".usuarios_",
            suffix=".tmp",
            delete=False,
        ) as f:
            arquivo_temp = f.name
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(arquivo_temp, NOME_ARQUIVO_USUARIOS)
    except Exception:
        if arquivo_temp and os.path.exists(arquivo_temp):
            try:
                os.remove(arquivo_temp)
            except OSError:
                pass
        raise


def _obter_senha_inicial_admin() -> str:
    senha_env = os.environ.get("ADMIN_INITIAL_PASSWORD", "").strip()
    if senha_env:
        return senha_env
    senha_gerada = f"Adm{secrets.token_urlsafe(10)}9"
    logging.warning(
        "🔐 Arquivo de usuários não encontrado. Conta inicial 'admin' criada com senha gerada: %s "
        "(defina ADMIN_INITIAL_PASSWORD ou altere a senha imediatamente após o primeiro login).",
        senha_gerada,
    )
    return senha_gerada


def carregar_usuarios() -> Dict[str, Any]:
    with _AUTH_LOCK:
        try:
            with open(NOME_ARQUIVO_USUARIOS, "r", encoding="utf-8-sig") as f:
                usuarios = json.load(f)
                if not isinstance(usuarios, dict):
                    raise json.JSONDecodeError("Formato inválido", "", 0)
                if "admin" in usuarios and usuarios["admin"].get("role") != "admin":
                    usuarios["admin"]["role"] = "admin"
                    _salvar_arquivo_usuarios(usuarios)
                return usuarios
        except (FileNotFoundError, json.JSONDecodeError):
            usuarios_iniciais = {
                "admin": {
                    "hash": gerar_hash_senha(_obter_senha_inicial_admin()),
                    "nome": "Administrador UFU",
                    "role": "admin",
                }
            }
            _salvar_arquivo_usuarios(usuarios_iniciais)
            return usuarios_iniciais


def salvar_usuario(usuario: str, senha: str, nome: str, role: str = "user") -> Tuple[bool, str]:
    valido_login, login_ou_erro = validar_login(usuario)
    if not valido_login:
        return False, login_ou_erro
    login_norm = login_ou_erro

    nome_limpo = sanitizar_texto(nome, max_len=100)
    if not nome_limpo:
        return False, "O nome completo é obrigatório."

    if role not in ROLES_VALIDOS:
        return False, "Perfil de acesso inválido! Use 'user' ou 'admin'."

    senha_ok, erro_senha = validar_senha_forte(senha)
    if not senha_ok:
        return False, erro_senha

    with _AUTH_LOCK:
        usuarios = carregar_usuarios()
        if login_norm in usuarios:
            return False, f"O usuário '{login_norm}' já está cadastrado!"

        nome_norm = nome_limpo.lower()
        for dados_existentes in usuarios.values():
            if str(dados_existentes.get("nome", "")).strip().lower() == nome_norm:
                return False, f"Já existe um usuário cadastrado com o nome '{nome_limpo}'!"

        usuarios[login_norm] = {
            "hash": gerar_hash_senha(senha),
            "nome": nome_limpo,
            "role": role,
        }
        _salvar_arquivo_usuarios(usuarios)

    return True, f"Usuário '{login_norm}' cadastrado com sucesso!"


def atualizar_role_usuario(usuario: str, novo_role: str) -> bool:
    if novo_role not in ROLES_VALIDOS:
        return False
    login_norm = str(usuario or "").strip().lower()
    if login_norm == "admin" and novo_role != "admin":
        return False

    with _AUTH_LOCK:
        usuarios = carregar_usuarios()
        if login_norm in usuarios:
            usuarios[login_norm]["role"] = novo_role
            _salvar_arquivo_usuarios(usuarios)
            return True
        return False


def deletar_usuario(usuario: str) -> Tuple[bool, str]:
    login_norm = str(usuario or "").strip().lower()
    if login_norm == "admin":
        return False, "O usuário 'admin' padrão não pode ser removido!"

    with _AUTH_LOCK:
        usuarios = carregar_usuarios()
        if login_norm in usuarios:
            del usuarios[login_norm]
            _salvar_arquivo_usuarios(usuarios)
            GERENCIADOR_SESSOES.invalidar_sessoes_usuario(login_norm)
            return True, f"Usuário '{login_norm}' removido com sucesso!"
        return False, "Usuário não encontrado."


def alterar_senha_usuario(
    login_id: str, senha_atual: str, nova_senha: str, token_atual: Optional[str] = None
) -> Tuple[bool, str]:
    senha_ok, erro_senha = validar_senha_forte(nova_senha)
    if not senha_ok:
        return False, erro_senha

    if senha_atual == nova_senha:
        return False, "A nova senha deve ser diferente da senha atual."

    login_norm = str(login_id or "").strip().lower()

    with _AUTH_LOCK:
        usuarios = carregar_usuarios()
        if login_norm not in usuarios:
            return False, "Usuário não encontrado!"

        if not verificar_senha(senha_atual, usuarios[login_norm]["hash"]):
            return False, "Senha atual incorreta!"

        usuarios[login_norm]["hash"] = gerar_hash_senha(nova_senha)
        _salvar_arquivo_usuarios(usuarios)

    GERENCIADOR_SESSOES.invalidar_sessoes_usuario(login_norm, manter_token=token_atual)
    return True, "Senha alterada com sucesso!"


def autenticar_usuario(usuario: str, senha: str) -> Tuple[bool, Any]:
    login_norm = str(usuario or "").strip().lower()
    if not login_norm or not isinstance(senha, str) or not senha:
        return False, "Usuário ou senha incorretos!"

    with _AUTH_LOCK:
        usuarios = carregar_usuarios()
        dados = usuarios.get(login_norm)
        if dados and verificar_senha(senha, dados.get("hash", "")):
            if _hash_e_legado(dados.get("hash", "")):
                dados["hash"] = gerar_hash_senha(senha)
                _salvar_arquivo_usuarios(usuarios)
            return True, {
                "nome": dados.get("nome", login_norm),
                "role": dados.get("role", "user"),
                "login_id": login_norm,
            }
    return False, "Usuário ou senha incorretos!"


class SessionManager:

    def __init__(self, ttl_segundos: int = SESSION_TTL_PADRAO):
        self._lock = threading.RLock()
        self._ttl = ttl_segundos
        self._sessoes: Dict[str, Dict[str, Any]] = {}

    def _limpar_expiradas(self) -> None:
        agora = time.time()
        expirados = [t for t, s in self._sessoes.items() if s["expira_em"] <= agora]
        for t in expirados:
            del self._sessoes[t]

    def criar_sessao(self, dados_usuario: Dict[str, Any]) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._limpar_expiradas()
            self._sessoes[token] = {
                "login_id": dados_usuario["login_id"],
                "nome": dados_usuario["nome"],
                "role": dados_usuario["role"],
                "criada_em": time.time(),
                "expira_em": time.time() + self._ttl,
            }
        return token

    def validar_sessao(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token or not isinstance(token, str):
            return None
        with self._lock:
            sessao = self._sessoes.get(token)
            if not sessao:
                return None
            if sessao["expira_em"] <= time.time():
                del self._sessoes[token]
                return None
            login_id = sessao["login_id"]

        usuarios = carregar_usuarios()
        dados_atuais = usuarios.get(login_id)
        if not dados_atuais:
            self.invalidar_sessao(token)
            return None

        return {
            "login_id": login_id,
            "nome": dados_atuais.get("nome", login_id),
            "role": dados_atuais.get("role", "user"),
        }

    def invalidar_sessao(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessoes.pop(token, None)

    def invalidar_sessoes_usuario(
        self, login_id: str, manter_token: Optional[str] = None
    ) -> None:
        with self._lock:
            tokens_remover = [
                t
                for t, s in self._sessoes.items()
                if s["login_id"] == login_id and t != manter_token
            ]
            for t in tokens_remover:
                del self._sessoes[t]

    def limpar_tudo(self) -> None:
        with self._lock:
            self._sessoes.clear()


class LoginRateLimiter:

    def __init__(
        self,
        max_tentativas_conta: int = 5,
        max_tentativas_ip: int = 15,
        janela_segundos: int = 300,
    ):
        self._lock = threading.RLock()
        self._max_conta = max_tentativas_conta
        self._max_ip = max_tentativas_ip
        self._janela = janela_segundos
        self._falhas_conta: Dict[Tuple[str, str], List[float]] = {}
        self._falhas_ip: Dict[str, List[float]] = {}

    def _podar(self, registros: List[float], agora: float) -> List[float]:
        limite = agora - self._janela
        return [ts for ts in registros if ts > limite]

    def esta_bloqueado(self, ip: str, usuario: str) -> Tuple[bool, int]:
        agora = time.time()
        chave = (ip, str(usuario or "").strip().lower())
        with self._lock:
            lista_conta = self._podar(self._falhas_conta.get(chave, []), agora)
            if lista_conta:
                self._falhas_conta[chave] = lista_conta
            else:
                self._falhas_conta.pop(chave, None)

            lista_ip = self._podar(self._falhas_ip.get(ip, []), agora)
            if lista_ip:
                self._falhas_ip[ip] = lista_ip
            else:
                self._falhas_ip.pop(ip, None)

            if len(lista_conta) >= self._max_conta:
                restante = max(1, int(self._janela - (agora - lista_conta[0])))
                return True, restante
            if len(lista_ip) >= self._max_ip:
                restante = max(1, int(self._janela - (agora - lista_ip[0])))
                return True, restante
            return False, 0

    def registrar_falha(self, ip: str, usuario: str) -> None:
        agora = time.time()
        chave = (ip, str(usuario or "").strip().lower())
        with self._lock:
            self._falhas_conta.setdefault(chave, []).append(agora)
            self._falhas_ip.setdefault(ip, []).append(agora)

    def limpar_falhas(self, ip: str, usuario: str) -> None:
        chave = (ip, str(usuario or "").strip().lower())
        with self._lock:
            self._falhas_conta.pop(chave, None)

    def limpar_tudo(self) -> None:
        with self._lock:
            self._falhas_conta.clear()
            self._falhas_ip.clear()


GERENCIADOR_SESSOES = SessionManager()
LIMITADOR_LOGIN = LoginRateLimiter()
