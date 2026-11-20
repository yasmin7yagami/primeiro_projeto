import http.cookies
import http.server
import json
import logging
import mimetypes
import os
import signal
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
if DIRETORIO_ATUAL not in sys.path:
    sys.path.insert(0, DIRETORIO_ATUAL)

from config import NOME_ARQUIVO_ATIVOS
from repositories import JsonAtivoRepository
from services.asset_service import AssetService
from services.audit_service import listar_eventos, registrar_evento
from services.auth_service import (
    GERENCIADOR_SESSOES,
    LIMITADOR_LOGIN,
    SESSION_TTL_PADRAO,
    alterar_senha_usuario,
    autenticar_usuario,
    carregar_usuarios,
    deletar_usuario,
    salvar_usuario,
)
from services.cve_service import consultar_cve_nvd, obter_mapa_severidades_locais
from services.risco_service import RiscoLinearService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (Web-Daemon) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

PORTA = int(os.environ.get("PORT", 8000))
PASTA_WEB = os.path.realpath(os.path.join(DIRETORIO_ATUAL, "web"))
HORA_INICIO = time.time()
MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "").strip()
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "").strip().lower() in ("1", "true", "yes")
EXTENSOES_ESTATICAS_PERMITIDAS = {
    ".html",
    ".css",
    ".js",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".ico",
    ".woff2",
}
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)

REPO = JsonAtivoRepository(caminho_arquivo=NOME_ARQUIVO_ATIVOS)
SERVICO_ATIVOS = AssetService(repositorio=REPO)
SERVICO_RISCO = RiscoLinearService(repositorio=REPO)


class DaemonMonitorThread(threading.Thread):

    def __init__(self, intervalo_segundos: int = 60):
        super().__init__(daemon=True, name="Monitor24hThread")
        self.intervalo = intervalo_segundos
        self.ativo = True

    def run(self):
        logging.info("🚀 Monitor 24 Horas ativado: auditoria contínua de integridade iniciada.")
        while self.ativo:
            try:
                uptime_minutos = int((time.time() - HORA_INICIO) / 60)
                severidades = obter_mapa_severidades_locais()
                resultado = SERVICO_RISCO.calcular_risco(severidades_cve=severidades)
                total_ativos = len(REPO.listar_todos())
                logging.info(
                    f"💓 Heartbeat 24h | Uptime: {uptime_minutos} min | Ativos: {total_ativos} | "
                    f"Invertível: {resultado.invertivel} | Det(I-A): {resultado.determinante:.4f}"
                )
            except Exception as e:
                logging.error(f"⚠️ Erro no ciclo de monitoramento daemon: {e}")
            time.sleep(self.intervalo)

    def parar(self):
        self.ativo = False


class InventarioHttpHandler(http.server.BaseHTTPRequestHandler):

    server_version = "InventarioServer"
    sys_version = ""

    def log_message(self, format, *args):
        logging.info(f"HTTP {self.command} {self.path} - {args[1] if len(args) > 1 else ''}")

    def _obter_ip_cliente(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _eh_https(self) -> bool:
        if HTTPS_ENABLED:
            return True
        return self.headers.get("X-Forwarded-Proto", "").strip().lower() == "https"

    def _extrair_token(self) -> Optional[str]:
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                return token

        cookie_header = self.headers.get("Cookie", "")
        if cookie_header:
            jar = http.cookies.SimpleCookie()
            try:
                jar.load(cookie_header)
                if "sid" in jar:
                    return jar["sid"].value.strip() or None
            except http.cookies.CookieError:
                return None
        return None

    def _obter_sessao(self) -> Optional[Dict[str, Any]]:
        token = self._extrair_token()
        return GERENCIADOR_SESSOES.validar_sessao(token)

    def _exigir_autenticacao(self, apenas_admin: bool = False) -> Optional[Dict[str, Any]]:
        sessao = self._obter_sessao()
        if not sessao:
            self._responder_json(
                401,
                {
                    "sucesso": False,
                    "mensagem": "Autenticação obrigatória. Faça login para continuar.",
                },
            )
            return None

        if apenas_admin and sessao.get("role") != "admin":
            registrar_evento(
                "ACESSO_NEGADO_ADMIN",
                usuario=sessao.get("login_id", "desconhecido"),
                ip=self._obter_ip_cliente(),
                recurso=self.path,
                sucesso=False,
            )
            self._responder_json(
                403,
                {
                    "sucesso": False,
                    "mensagem": "Acesso negado. Permissão de administrador necessária.",
                },
            )
            return None

        return sessao

    def _enviar_headers_seguranca(self, eh_api: bool = True, eh_html: bool = False):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        if eh_api:
            self.send_header("Cache-Control", "no-store")
        if eh_html:
            self.send_header("Content-Security-Policy", CSP_POLICY)

        origin = self.headers.get("Origin", "").strip()
        if ALLOWED_ORIGIN and origin == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Vary", "Origin")

    def _ler_corpo_json(self) -> Tuple[Optional[Dict[str, Any]], Optional[int], Optional[str]]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_length)
        except ValueError:
            return None, 400, "Cabeçalho Content-Length inválido."

        if content_length < 0:
            return None, 400, "Cabeçalho Content-Length inválido."
        if content_length > MAX_BODY_BYTES:
            return None, 413, "Payload excede o limite máximo permitido (1 MB)."
        if content_length == 0:
            return {}, None, None

        try:
            corpo_bytes = self.rfile.read(content_length)
            corpo_texto = corpo_bytes.decode("utf-8")
            dados = json.loads(corpo_texto)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, 400, "Corpo JSON inválido."

        if not isinstance(dados, dict):
            return None, 400, "O corpo da requisição deve ser um objeto JSON."
        return dados, None, None

    def _responder_json(
        self,
        status_code: int,
        dados: Dict[str, Any],
        headers_extras: Optional[List[Tuple[str, str]]] = None,
    ):
        conteudo = json.dumps(dados, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(conteudo)))
        self._enviar_headers_seguranca(eh_api=True)
        if headers_extras:
            for chave, valor in headers_extras:
                self.send_header(chave, valor)
        self.end_headers()
        self.wfile.write(conteudo)

    def _montar_cookie_sessao(self, token: str, max_age: int) -> str:
        partes = [
            f"sid={token}",
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            f"Max-Age={max_age}",
        ]
        if self._eh_https():
            partes.append("Secure")
        return "; ".join(partes)

    def _servir_arquivo_estatico(self, caminho_relativo: str):
        caminho_decodificado = unquote(caminho_relativo)
        if "\x00" in caminho_decodificado or "\\" in caminho_decodificado:
            registrar_evento(
                "PATH_TRAVERSAL_BLOQUEADO",
                ip=self._obter_ip_cliente(),
                recurso=caminho_relativo,
                sucesso=False,
            )
            self._responder_json(403, {"erro": "Caminho inválido."})
            return

        if caminho_decodificado in ("", "/", "/index.html"):
            nome_limpo = "index.html"
        else:
            nome_limpo = caminho_decodificado.lstrip("/")

        segmentos = nome_limpo.split("/")
        if any(seg in ("..", ".") or seg == "" for seg in segmentos):
            registrar_evento(
                "PATH_TRAVERSAL_BLOQUEADO",
                ip=self._obter_ip_cliente(),
                recurso=caminho_relativo,
                sucesso=False,
            )
            self._responder_json(403, {"erro": "Acesso negado."})
            return

        arquivo_alvo = os.path.realpath(os.path.join(PASTA_WEB, *segmentos))
        try:
            dentro_pasta_web = os.path.commonpath([PASTA_WEB, arquivo_alvo]) == PASTA_WEB
        except ValueError:
            dentro_pasta_web = False

        if not dentro_pasta_web:
            registrar_evento(
                "PATH_TRAVERSAL_BLOQUEADO",
                ip=self._obter_ip_cliente(),
                recurso=caminho_relativo,
                sucesso=False,
            )
            self._responder_json(403, {"erro": "Acesso negado."})
            return

        _, extensao = os.path.splitext(arquivo_alvo)
        if extensao.lower() not in EXTENSOES_ESTATICAS_PERMITIDAS:
            self._responder_json(403, {"erro": "Tipo de arquivo não permitido."})
            return

        if not os.path.isfile(arquivo_alvo):
            self._responder_json(404, {"erro": "Arquivo estático não encontrado."})
            return

        mime_type, _ = mimetypes.guess_type(arquivo_alvo)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            with open(arquivo_alvo, "rb") as f:
                conteudo = f.read()

            self.send_response(200)
            if mime_type.startswith("text/") or mime_type in ("application/javascript", "text/javascript"):
                self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
            else:
                self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(conteudo)))
            self._enviar_headers_seguranca(eh_api=False, eh_html=(extensao.lower() == ".html"))
            self.end_headers()
            self.wfile.write(conteudo)
        except OSError:
            self._responder_json(500, {"erro": "Erro ao ler arquivo estático."})

    @staticmethod
    def _classificar_status_erro(mensagem: str) -> int:
        msg_low = mensagem.lower()
        if "não encontrado" in msg_low or "não existe" in msg_low:
            return 404
        if "já existe" in msg_low or "já está" in msg_low or "duplicada" in msg_low:
            return 409
        return 400

    def do_OPTIONS(self):
        self.send_response(204)
        self._enviar_headers_seguranca(eh_api=True)
        self.end_headers()

    def do_GET(self):
        try:
            self._processar_get()
        except Exception:
            logging.exception("Erro interno ao processar GET %s", self.path)
            self._responder_json(500, {"sucesso": False, "mensagem": "Erro interno no servidor."})

    def _processar_get(self):
        parsed_url = urlparse(self.path)
        caminho = parsed_url.path
        params = parse_qs(parsed_url.query)

        if caminho in ("/api/health", "/health"):
            uptime = int(time.time() - HORA_INICIO)
            self._responder_json(200, {
                "status": "UP",
                "servico": "UFU Ciberseguranca - Inventario e Analise de Risco",
                "requisito_container_24h": "Ativo e Saudavel",
                "uptime_segundos": uptime,
                "uptime_horas": round(uptime / 3600, 2),
                "total_ativos": len(REPO.listar_todos()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return

        if caminho == "/api/me":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            self._responder_json(200, {"sucesso": True, "usuario": sessao})
            return

        if caminho == "/api/ativos":
            if not self._exigir_autenticacao():
                return
            ativos = [ativo.to_dict() for ativo in SERVICO_ATIVOS.obter_base_ativos().values()]
            self._responder_json(200, {"sucesso": True, "total": len(ativos), "ativos": ativos})
            return

        if caminho == "/api/risco":
            if not self._exigir_autenticacao():
                return
            severidades = obter_mapa_severidades_locais()
            resultado = SERVICO_RISCO.calcular_risco(severidades_cve=severidades)
            self._responder_json(200, resultado.to_dict())
            return

        if caminho == "/api/auditoria":
            if not self._exigir_autenticacao(apenas_admin=True):
                return
            limite = params.get("limite", ["50"])[0]
            eventos = listar_eventos(limite=limite)
            self._responder_json(200, {"sucesso": True, "total": len(eventos), "eventos": eventos})
            return

        if caminho == "/api/cve/consultar":
            if not self._exigir_autenticacao():
                return
            codigo = params.get("codigo", [""])[0]
            if not codigo:
                self._responder_json(400, {"erro": "Parâmetro 'codigo' é obrigatório."})
                return
            dados_cve = consultar_cve_nvd(codigo)
            status = 400 if "erro" in dados_cve and "inválido" in dados_cve["erro"].lower() else 200
            self._responder_json(status, dados_cve)
            return

        if caminho == "/api/usuarios":
            if not self._exigir_autenticacao(apenas_admin=True):
                return
            usuarios = carregar_usuarios()
            usuarios_sanitizados = {
                k: {"nome": v.get("nome", k), "role": v.get("role", "user")}
                for k, v in usuarios.items()
            }
            self._responder_json(200, {"sucesso": True, "usuarios": usuarios_sanitizados})
            return

        if caminho.startswith("/api/"):
            self._responder_json(404, {"erro": "Rota GET não encontrada."})
            return

        self._servir_arquivo_estatico(caminho)

    def do_POST(self):
        try:
            self._processar_post()
        except Exception:
            logging.exception("Erro interno ao processar POST %s", self.path)
            self._responder_json(500, {"sucesso": False, "mensagem": "Erro interno no servidor."})

    def _processar_post(self):
        caminho = urlparse(self.path).path

        if caminho == "/api/logout":
            token = self._extrair_token()
            sessao = GERENCIADOR_SESSOES.validar_sessao(token)
            GERENCIADOR_SESSOES.invalidar_sessao(token)
            if sessao:
                registrar_evento(
                    "LOGOUT",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso="/api/logout",
                )
            cookie_limpo = self._montar_cookie_sessao("", 0)
            self._responder_json(
                200,
                {"sucesso": True, "mensagem": "Sessão encerrada com sucesso."},
                headers_extras=[("Set-Cookie", cookie_limpo)],
            )
            return

        corpo, erro_status, erro_msg = self._ler_corpo_json()
        if erro_status is not None or corpo is None:
            self._responder_json(erro_status or 400, {"sucesso": False, "mensagem": erro_msg or "Requisição inválida."})
            return

        if caminho == "/api/login":
            ip_cliente = self._obter_ip_cliente()
            usuario = str(corpo.get("usuario", "")).strip().lower()
            senha = corpo.get("senha", "")
            if not isinstance(senha, str):
                self._responder_json(400, {"sucesso": False, "mensagem": "Credenciais inválidas."})
                return

            bloqueado, segundos = LIMITADOR_LOGIN.esta_bloqueado(ip_cliente, usuario)
            if bloqueado:
                registrar_evento(
                    "LOGIN_BLOQUEADO_RATE_LIMIT",
                    usuario=usuario or "anonimo",
                    ip=ip_cliente,
                    recurso="/api/login",
                    detalhes={"aguardar_segundos": segundos},
                    sucesso=False,
                )
                self._responder_json(
                    429,
                    {
                        "sucesso": False,
                        "mensagem": f"Muitas tentativas de login. Aguarde {segundos} segundos e tente novamente.",
                    },
                    headers_extras=[("Retry-After", str(segundos))],
                )
                return

            sucesso, resultado = autenticar_usuario(usuario, senha)
            if sucesso:
                LIMITADOR_LOGIN.limpar_falhas(ip_cliente, usuario)
                token = GERENCIADOR_SESSOES.criar_sessao(resultado)
                cookie = self._montar_cookie_sessao(token, SESSION_TTL_PADRAO)
                registrar_evento(
                    "LOGIN_SUCESSO",
                    usuario=resultado["login_id"],
                    ip=ip_cliente,
                    recurso="/api/login",
                    detalhes={"role": resultado["role"]},
                )
                self._responder_json(
                    200,
                    {"sucesso": True, "usuario": resultado},
                    headers_extras=[("Set-Cookie", cookie)],
                )
            else:
                LIMITADOR_LOGIN.registrar_falha(ip_cliente, usuario)
                registrar_evento(
                    "LOGIN_FALHA",
                    usuario=usuario or "anonimo",
                    ip=ip_cliente,
                    recurso="/api/login",
                    sucesso=False,
                )
                self._responder_json(401, {"sucesso": False, "mensagem": resultado})
            return

        if caminho == "/api/alterar-senha":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            senha_atual = corpo.get("senha_atual", "")
            nova_senha = corpo.get("nova_senha", "")
            token_atual = self._extrair_token()
            sucesso, msg = alterar_senha_usuario(
                sessao["login_id"], senha_atual, nova_senha, token_atual=token_atual
            )
            registrar_evento(
                "SENHA_ALTERADA",
                usuario=sessao["login_id"],
                ip=self._obter_ip_cliente(),
                recurso=f"usuario:{sessao['login_id']}",
                sucesso=sucesso,
            )
            self._responder_json(200 if sucesso else 400, {"sucesso": sucesso, "mensagem": msg})
            return

        if caminho == "/api/ativos":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return

            id_raw = corpo.get("id_ativo")
            hostname = corpo.get("hostname", "")
            responsavel = corpo.get("responsavel", "")
            localizacao = corpo.get("localizacao", "")
            tipo = corpo.get("tipo", "")
            vulnerabilidades = corpo.get("vulnerabilidades")
            extras = {
                k: v
                for k, v in corpo.items()
                if k
                not in {
                    "id",
                    "id_ativo",
                    "hostname",
                    "responsavel",
                    "localizacao",
                    "tipo",
                    "vulnerabilidades",
                    "dependencias",
                }
            }

            sucesso, msg = SERVICO_ATIVOS.cadastrar_ativo(
                id_str=id_raw,
                hostname_bruto=hostname,
                responsavel_bruto=responsavel,
                localizacao_bruto=localizacao,
                tipo=tipo,
                vulnerabilidades=vulnerabilidades,
                **extras,
            )
            if sucesso:
                ativo_criado = SERVICO_ATIVOS.obter_ativo(int(str(id_raw).strip()))
                registrar_evento(
                    "ATIVO_CRIADO",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{id_raw}",
                    detalhes={"hostname": ativo_criado.hostname if ativo_criado else hostname, "tipo": tipo},
                )
                self._responder_json(
                    201,
                    {
                        "sucesso": True,
                        "mensagem": msg,
                        "ativo": ativo_criado.to_dict() if ativo_criado else None,
                    },
                )
            else:
                status = self._classificar_status_erro(msg)
                self._responder_json(status, {"sucesso": False, "mensagem": msg})
            return

        partes = [p for p in caminho.split("/") if p]

        if len(partes) == 4 and partes[0] == "api" and partes[1] == "ativos" and partes[3] == "cves":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            id_str = partes[2]
            cve = corpo.get("cve", "")
            if not isinstance(cve, str) or not cve.strip():
                self._responder_json(400, {"sucesso": False, "mensagem": "Código CVE obrigatório."})
                return

            sucesso, msg = SERVICO_ATIVOS.vincular_cve_ao_ativo(id_str, cve)
            if sucesso:
                registrar_evento(
                    "CVE_VINCULADA",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{id_str}",
                    detalhes={"cve": cve.strip().upper()},
                )
                self._responder_json(200, {"sucesso": True, "mensagem": msg})
            else:
                status = self._classificar_status_erro(msg)
                self._responder_json(status, {"sucesso": False, "mensagem": msg})
            return

        if len(partes) == 4 and partes[0] == "api" and partes[1] == "ativos" and partes[3] == "dependencias":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            id_origem = partes[2]
            id_alvo = corpo.get("id_alvo")
            peso = corpo.get("peso")
            sucesso, msg = SERVICO_ATIVOS.adicionar_dependencia(id_origem, id_alvo, peso)
            if sucesso:
                registrar_evento(
                    "DEPENDENCIA_ADICIONADA",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{id_origem}",
                    detalhes={"id_alvo": id_alvo, "peso": peso},
                )
                self._responder_json(200, {"sucesso": True, "mensagem": msg})
            else:
                status = self._classificar_status_erro(msg)
                self._responder_json(status, {"sucesso": False, "mensagem": msg})
            return

        if caminho == "/api/usuarios":
            sessao = self._exigir_autenticacao(apenas_admin=True)
            if not sessao:
                return
            usuario = corpo.get("usuario", "")
            nome = corpo.get("nome", "")
            senha = corpo.get("senha", "")
            role = corpo.get("role", "user")

            sucesso, msg = salvar_usuario(usuario, senha, nome, role)
            registrar_evento(
                "USUARIO_CRIADO",
                usuario=sessao["login_id"],
                ip=self._obter_ip_cliente(),
                recurso=f"usuario:{str(usuario).strip().lower()}",
                detalhes={"role": role},
                sucesso=sucesso,
            )
            if sucesso:
                self._responder_json(201, {"sucesso": True, "mensagem": msg})
            else:
                status = self._classificar_status_erro(msg)
                self._responder_json(status, {"sucesso": False, "mensagem": msg})
            return

        self._responder_json(404, {"erro": "Rota POST não encontrada."})

    def do_PUT(self):
        try:
            self._processar_put()
        except Exception:
            logging.exception("Erro interno ao processar PUT %s", self.path)
            self._responder_json(500, {"sucesso": False, "mensagem": "Erro interno no servidor."})

    def _processar_put(self):
        caminho = urlparse(self.path).path
        corpo, erro_status, erro_msg = self._ler_corpo_json()
        if erro_status is not None or corpo is None:
            self._responder_json(erro_status or 400, {"sucesso": False, "mensagem": erro_msg or "Requisição inválida."})
            return

        partes = [p for p in caminho.split("/") if p]
        if len(partes) == 3 and partes[0] == "api" and partes[1] == "ativos":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            id_str = partes[2]
            hostname = corpo.get("hostname", "")
            responsavel = corpo.get("responsavel", "")
            localizacao = corpo.get("localizacao", "")
            tipo = corpo.get("tipo", "")
            extras = {
                k: v
                for k, v in corpo.items()
                if k
                not in {
                    "id",
                    "id_ativo",
                    "hostname",
                    "responsavel",
                    "localizacao",
                    "tipo",
                    "vulnerabilidades",
                    "dependencias",
                }
            }

            sucesso, msg = SERVICO_ATIVOS.atualizar_ativo(
                id_str=id_str,
                hostname_bruto=hostname,
                responsavel_bruto=responsavel,
                localizacao_bruto=localizacao,
                tipo=tipo,
                **extras,
            )
            if sucesso:
                ativo_atualizado = SERVICO_ATIVOS.obter_ativo(int(id_str))
                registrar_evento(
                    "ATIVO_ATUALIZADO",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{id_str}",
                    detalhes={"hostname": ativo_atualizado.hostname if ativo_atualizado else hostname},
                )
                self._responder_json(
                    200,
                    {
                        "sucesso": True,
                        "mensagem": msg,
                        "ativo": ativo_atualizado.to_dict() if ativo_atualizado else None,
                    },
                )
            else:
                status = self._classificar_status_erro(msg)
                self._responder_json(status, {"sucesso": False, "mensagem": msg})
            return

        self._responder_json(404, {"erro": "Rota PUT não encontrada."})

    def do_DELETE(self):
        try:
            self._processar_delete()
        except Exception:
            logging.exception("Erro interno ao processar DELETE %s", self.path)
            self._responder_json(500, {"sucesso": False, "mensagem": "Erro interno no servidor."})

    def _processar_delete(self):
        caminho = urlparse(self.path).path
        partes = [p for p in caminho.split("/") if p]

        if len(partes) == 5 and partes[0] == "api" and partes[1] == "ativos" and partes[3] == "cves":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            id_ativo_str = partes[2]
            cve = unquote(partes[4])
            sucesso, msg = SERVICO_ATIVOS.desvincular_cve_do_ativo(id_ativo_str, cve)
            if sucesso:
                registrar_evento(
                    "CVE_REMOVIDA",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{id_ativo_str}",
                    detalhes={"cve": cve.strip().upper()},
                )
            status = 200 if sucesso else self._classificar_status_erro(msg)
            self._responder_json(status, {"sucesso": sucesso, "mensagem": msg})
            return

        if len(partes) == 5 and partes[0] == "api" and partes[1] == "ativos" and partes[3] == "dependencias":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            sucesso, msg = SERVICO_ATIVOS.remover_dependencia(partes[2], partes[4])
            if sucesso:
                registrar_evento(
                    "DEPENDENCIA_REMOVIDA",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{partes[2]}",
                    detalhes={"id_alvo": partes[4]},
                )
            status = 200 if sucesso else self._classificar_status_erro(msg)
            self._responder_json(status, {"sucesso": sucesso, "mensagem": msg})
            return

        if len(partes) == 3 and partes[0] == "api" and partes[1] == "ativos":
            sessao = self._exigir_autenticacao()
            if not sessao:
                return
            sucesso, msg = SERVICO_ATIVOS.deletar_ativo(partes[2])
            if sucesso:
                registrar_evento(
                    "ATIVO_EXCLUIDO",
                    usuario=sessao["login_id"],
                    ip=self._obter_ip_cliente(),
                    recurso=f"ativo:{partes[2]}",
                )
            status = 200 if sucesso else self._classificar_status_erro(msg)
            self._responder_json(status, {"sucesso": sucesso, "mensagem": msg})
            return

        if len(partes) == 3 and partes[0] == "api" and partes[1] == "usuarios":
            sessao = self._exigir_autenticacao(apenas_admin=True)
            if not sessao:
                return
            usuario = unquote(partes[2])
            sucesso, msg = deletar_usuario(usuario)
            registrar_evento(
                "USUARIO_EXCLUIDO",
                usuario=sessao["login_id"],
                ip=self._obter_ip_cliente(),
                recurso=f"usuario:{usuario.strip().lower()}",
                sucesso=sucesso,
            )
            status = 200 if sucesso else self._classificar_status_erro(msg)
            self._responder_json(status, {"sucesso": sucesso, "mensagem": msg})
            return

        self._responder_json(404, {"erro": "Rota DELETE não encontrada."})


class ServidorThreaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def iniciar_servidor():
    monitor = DaemonMonitorThread(intervalo_segundos=60)
    monitor.start()

    servidor = ServidorThreaded(("0.0.0.0", PORTA), InventarioHttpHandler)
    logging.info(f"🌐 Servidor Web ativo em http://0.0.0.0:{PORTA}")
    logging.info(f"📁 Servindo interface web a partir de: {PASTA_WEB}")

    def tratar_encerramento(signum, frame):
        logging.info("🛑 Sinal de encerramento recebido. Desligando container com segurança...")
        monitor.parar()
        threading.Thread(target=servidor.shutdown).start()

    signal.signal(signal.SIGINT, tratar_encerramento)
    signal.signal(signal.SIGTERM, tratar_encerramento)

    try:
        servidor.serve_forever()
    finally:
        servidor.server_close()
        logging.info("✅ Servidor finalizado com sucesso.")


if __name__ == "__main__":
    iniciar_servidor()
