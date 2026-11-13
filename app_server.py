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
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

# Garante importação dos módulos da raiz do projeto
DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
if DIRETORIO_ATUAL not in sys.path:
    sys.path.insert(0, DIRETORIO_ATUAL)

from config import NOME_ARQUIVO_ATIVOS
from models import AtivoFactory
from repositories import JsonAtivoRepository
from services.auth_service import (
    alterar_senha_usuario,
    autenticar_usuario,
    carregar_usuarios,
    deletar_usuario,
    salvar_usuario,
)
from services.cve_service import consultar_cve_nvd
from services.risco_service import RiscoLinearService

# Configuração de Logs Estruturados para Container Docker (Requisito 3 / S4_18)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (Web-Daemon) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

PORTA = int(os.environ.get("PORT", 8000))
PASTA_WEB = os.path.join(DIRETORIO_ATUAL, "web")
HORA_INICIO = time.time()
REPO = JsonAtivoRepository(caminho_arquivo=NOME_ARQUIVO_ATIVOS)
SERVICO_RISCO = RiscoLinearService(repositorio=REPO)


class DaemonMonitorThread(threading.Thread):
    """Thread daemon para monitoramento contínuo de integridade e auditoria 24h (Requisito 3)."""

    def __init__(self, intervalo_segundos: int = 60):
        super().__init__(daemon=True, name="Monitor24hThread")
        self.intervalo = intervalo_segundos
        self.ativo = True

    def run(self):
        logging.info("🚀 Monitor 24 Horas ativado: auditoria contínua de integridade iniciada.")
        while self.ativo:
            try:
                uptime_minutos = int((time.time() - HORA_INICIO) / 60)
                resultado = SERVICO_RISCO.calcular_risco()
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
    """Servidor HTTP REST e Servidor Estático de Web SPA para o Trabalho 02."""

    def log_message(self, format, *args):
        logging.info(f"HTTP {self.command} {self.path} - {args[1] if len(args) > 1 else ''}")

    def _ler_corpo_json(self) -> Dict[str, Any]:
        """Lê e desserializa o corpo JSON da requisição."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        corpo = self.rfile.read(content_length).decode("utf-8")
        try:
            return json.loads(corpo)
        except json.JSONDecodeError:
            return {}

    def _responder_json(self, status_code: int, dados: Dict[str, Any]):
        conteudo = json.dumps(dados, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(conteudo)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(conteudo)

    def _servir_arquivo_estatico(self, caminho_relativo: str):
        """Serve arquivos HTML, CSS e JS da pasta web/."""
        if caminho_relativo in ("", "/", "/index.html"):
            arquivo_alvo = os.path.join(PASTA_WEB, "index.html")
        else:
            nome_limpo = caminho_relativo.lstrip("/")
            arquivo_alvo = os.path.join(PASTA_WEB, nome_limpo)

        if not os.path.exists(arquivo_alvo) or os.path.isdir(arquivo_alvo):
            self._responder_json(404, {"erro": "Arquivo estático não encontrado."})
            return

        mime_type, _ = mimetypes.guess_type(arquivo_alvo)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            with open(arquivo_alvo, "rb") as f:
                conteudo = f.read()

            self.send_response(200)
            self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(conteudo)))
            self.end_headers()
            self.wfile.write(conteudo)
        except OSError:
            self._responder_json(500, {"erro": "Erro ao ler arquivo estático."})

    def do_OPTIONS(self):
        """Suporte a CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # =========================================================================
    # REQUISIÇÕES GET (Consultas e Arquivos Estáticos)
    # =========================================================================
    def do_GET(self):
        parsed_url = urlparse(self.path)
        caminho = parsed_url.path
        params = parse_qs(parsed_url.query)

        # 1. Healthcheck Contínuo para o Docker (Requisito 3)
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

        # 2. Listagem de Ativos (Requisito 2 - Lista JSON)
        if caminho == "/api/ativos":
            ativos = [ativo.to_dict() for ativo in REPO.listar_todos().values()]
            self._responder_json(200, {"sucesso": True, "total": len(ativos), "ativos": ativos})
            return

        # 3. Análise de Risco por Álgebra Linear (Requisito 4)
        if caminho == "/api/risco":
            resultado = SERVICO_RISCO.calcular_risco()
            self._responder_json(200, resultado.to_dict())
            return

        # 4. Consulta de CVE na API da NVD / Cache
        if caminho == "/api/cve/consultar":
            codigo = params.get("codigo", [""])[0]
            if not codigo:
                self._responder_json(400, {"erro": "Parâmetro 'codigo' é obrigatório."})
                return
            dados_cve = consultar_cve_nvd(codigo)
            self._responder_json(200, dados_cve)
            return

        # 5. Listagem de Usuários (Admin)
        if caminho == "/api/usuarios":
            usuarios = carregar_usuarios()
            usuarios_sanitizados = {
                k: {"nome": v.get("nome", k), "role": v.get("role", "user")}
                for k, v in usuarios.items()
            }
            self._responder_json(200, {"sucesso": True, "usuarios": usuarios_sanitizados})
            return

        # 6. Servir Frontend Web (SPA)
        self._servir_arquivo_estatico(caminho)

    # =========================================================================
    # REQUISIÇÕES POST (Criações e Autenticação)
    # =========================================================================
    def do_POST(self):
        caminho = urlparse(self.path).path
        corpo = self._ler_corpo_json()

        # 1. Login
        if caminho == "/api/login":
            usuario = corpo.get("usuario", "").strip().lower()
            senha = corpo.get("senha", "")
            sucesso, resultado = autenticar_usuario(usuario, senha)
            if sucesso:
                self._responder_json(200, {"sucesso": True, "usuario": resultado})
            else:
                self._responder_json(401, {"sucesso": False, "mensagem": resultado})
            return

        # 2. Alteração de Senha
        if caminho == "/api/alterar-senha":
            login_id = corpo.get("login_id", "").strip().lower()
            senha_atual = corpo.get("senha_atual", "")
            nova_senha = corpo.get("nova_senha", "")
            sucesso, msg = alterar_senha_usuario(login_id, senha_atual, nova_senha)
            self._responder_json(200 if sucesso else 400, {"sucesso": sucesso, "mensagem": msg})
            return

        # 3. Criar Novo Ativo (POO)
        if caminho == "/api/ativos":
            try:
                id_ativo = int(corpo.get("id_ativo", 0))
                if id_ativo <= 0:
                    self._responder_json(400, {"sucesso": False, "mensagem": "O ID deve ser um número inteiro positivo."})
                    return
                if REPO.existe(id_ativo):
                    self._responder_json(400, {"sucesso": False, "mensagem": f"O ID {id_ativo} já existe no inventário!"})
                    return

                novo_ativo = AtivoFactory.from_dict(id_ativo, corpo)
                sucesso = REPO.salvar(novo_ativo)
                self._responder_json(201 if sucesso else 500, {
                    "sucesso": sucesso,
                    "mensagem": f"Ativo '{novo_ativo.hostname}' registrado com sucesso!" if sucesso else "Falha ao persistir no arquivo JSON.",
                    "ativo": novo_ativo.to_dict(),
                })
            except Exception as e:
                self._responder_json(400, {"sucesso": False, "mensagem": f"Erro na criação do ativo: {e}"})
            return

        # 4. Vincular CVE a um Ativo (/api/ativos/<id>/cves)
        if caminho.startswith("/api/ativos/") and caminho.endswith("/cves"):
            partes = caminho.split("/")
            id_ativo = int(partes[3])
            ativo = REPO.obter_por_id(id_ativo)
            if not ativo:
                self._responder_json(404, {"sucesso": False, "mensagem": "Ativo não encontrado."})
                return

            cve = corpo.get("cve", "").strip().upper()
            if not cve:
                self._responder_json(400, {"sucesso": False, "mensagem": "Código CVE obrigatório."})
                return

            sucesso = ativo.adicionar_vulnerabilidade(cve)
            if sucesso:
                REPO.salvar(ativo)
                self._responder_json(200, {"sucesso": True, "mensagem": f"{cve} vinculada ao ativo {id_ativo}!"})
            else:
                self._responder_json(400, {"sucesso": False, "mensagem": "Esta CVE já está associada a este ativo."})
            return

        # 5. Adicionar Dependência entre Ativos (Matriz A) (/api/ativos/<id>/dependencias)
        if caminho.startswith("/api/ativos/") and caminho.endswith("/dependencias"):
            partes = caminho.split("/")
            id_ativo = int(partes[3])
            ativo = REPO.obter_por_id(id_ativo)
            if not ativo:
                self._responder_json(404, {"sucesso": False, "mensagem": "Ativo não encontrado."})
                return

            id_alvo = int(corpo.get("id_alvo", 0))
            peso = float(corpo.get("peso", 0.0))

            if not REPO.existe(id_alvo):
                self._responder_json(400, {"sucesso": False, "mensagem": f"O equipamento de destino (ID {id_alvo}) não existe."})
                return

            sucesso = ativo.adicionar_dependencia(id_alvo, peso)
            if sucesso:
                REPO.salvar(ativo)
                self._responder_json(200, {"sucesso": True, "mensagem": "Dependência de risco registrada com sucesso!"})
            else:
                self._responder_json(400, {
                    "sucesso": False,
                    "mensagem": "Dependência inválida! Regras: A_ii = 0, peso em [0, 1) e soma das dependências da linha < 1.0.",
                })
            return

        # 6. Criar Usuário (Admin)
        if caminho == "/api/usuarios":
            usuario = corpo.get("usuario", "").strip().lower()
            nome = corpo.get("nome", "").strip()
            senha = corpo.get("senha", "")
            role = corpo.get("role", "user")

            if not usuario or not senha:
                self._responder_json(400, {"sucesso": False, "mensagem": "Usuário e senha são obrigatórios."})
                return

            salvar_usuario(usuario, senha, nome, role)
            self._responder_json(201, {"sucesso": True, "mensagem": f"Usuário '{usuario}' cadastrado!"})
            return

        self._responder_json(404, {"erro": "Rota POST não encontrada."})

    # =========================================================================
    # REQUISIÇÕES PUT (Atualizações)
    # =========================================================================
    def do_PUT(self):
        caminho = urlparse(self.path).path
        corpo = self._ler_corpo_json()

        # Atualizar Ativo (/api/ativos/<id>)
        if caminho.startswith("/api/ativos/"):
            id_str = caminho.split("/")[-1]
            try:
                id_ativo = int(id_str)
            except ValueError:
                self._responder_json(400, {"sucesso": False, "mensagem": "ID inválido."})
                return

            ativo = REPO.obter_por_id(id_ativo)
            if not ativo:
                self._responder_json(404, {"sucesso": False, "mensagem": "Ativo não encontrado."})
                return

            # Preserva vulnerabilidades e dependências existentes
            vuls = list(ativo.vulnerabilidades)
            deps = dict(ativo.obter_dependencias())

            corpo["id_ativo"] = id_ativo
            corpo["vulnerabilidades"] = vuls
            corpo["dependencias"] = deps

            novo_ativo = AtivoFactory.from_dict(id_ativo, corpo)
            sucesso = REPO.salvar(novo_ativo)
            self._responder_json(200 if sucesso else 500, {
                "sucesso": sucesso,
                "mensagem": "Ativo atualizado com sucesso!" if sucesso else "Erro ao salvar atualização.",
                "ativo": novo_ativo.to_dict(),
            })
            return

        self._responder_json(404, {"erro": "Rota PUT não encontrada."})

    # =========================================================================
    # REQUISIÇÕES DELETE (Exclusões)
    # =========================================================================
    def do_DELETE(self):
        caminho = urlparse(self.path).path

        # 1. Remover Dependência (/api/ativos/<id>/dependencias/<id_alvo>)
        if "/dependencias/" in caminho:
            partes = caminho.split("/")
            id_ativo = int(partes[3])
            id_alvo = int(partes[5])

            ativo = REPO.obter_por_id(id_ativo)
            if ativo and ativo.remover_dependencia(id_alvo):
                REPO.salvar(ativo)
                self._responder_json(200, {"sucesso": True, "mensagem": "Dependência removida com sucesso!"})
            else:
                self._responder_json(404, {"sucesso": False, "mensagem": "Dependência não encontrada."})
            return

        # 2. Remover Ativo (/api/ativos/<id>)
        if caminho.startswith("/api/ativos/"):
            id_str = caminho.split("/")[-1]
            try:
                id_ativo = int(id_str)
            except ValueError:
                self._responder_json(400, {"sucesso": False, "mensagem": "ID inválido."})
                return

            sucesso = REPO.remover(id_ativo)
            self._responder_json(200 if sucesso else 404, {
                "sucesso": sucesso,
                "mensagem": f"Ativo {id_ativo} removido!" if sucesso else "Ativo não encontrado.",
            })
            return

        # 3. Remover Usuário (/api/usuarios/<login>)
        if caminho.startswith("/api/usuarios/"):
            usuario = caminho.split("/")[-1]
            sucesso, msg = deletar_usuario(usuario)
            self._responder_json(200 if sucesso else 400, {"sucesso": sucesso, "mensagem": msg})
            return

        self._responder_json(404, {"erro": "Rota DELETE não encontrada."})


class ServidorThreaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Servidor HTTP multithread para alta concorrência e estabilidade 24 horas."""
    daemon_threads = True
    allow_reuse_address = True


def iniciar_servidor():
    """Inicia o servidor web e a thread de monitoramento contínuo com captura de sinais."""
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
