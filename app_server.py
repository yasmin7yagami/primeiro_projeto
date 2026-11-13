import http.server
import json
import logging
import os
import signal
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict

# Garante importação dos módulos locais
DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
if DIRETORIO_ATUAL not in sys.path:
    sys.path.insert(0, DIRETORIO_ATUAL)

from config import NOME_ARQUIVO_ATIVOS
from repositories import JsonAtivoRepository
from services.risco_service import RiscoLinearService

# Configuração de Logs Estruturados para Auditoria Docker (Requisito 3 / S4_18)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (Container-Daemon) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

PORTA = int(os.environ.get("PORT", 8000))
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
    """Servidor HTTP REST e Dashboard Web para o Trabalho 02 (execução estável em container)."""

    def log_message(self, format, *args):
        # Redireciona logs de requisição para o logger padrão do container
        logging.info(f"HTTP {self.command} {self.path} - {args[1] if len(args) > 1 else ''}")

    def _responder_json(self, status_code: int, dados: Dict[str, Any]):
        conteudo = json.dumps(dados, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(conteudo)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(conteudo)

    def _responder_html(self, status_code: int, html_str: str):
        conteudo = html_str.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(conteudo)))
        self.end_headers()
        self.wfile.write(conteudo)

    def do_GET(self):
        caminho = self.path.split("?")[0]

        # 1. Healthcheck para o Docker (HEALTHCHECK)
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

        # 2. API de Análise de Risco (Requisito 4 - Álgebra Linear)
        if caminho == "/api/risco":
            resultado = SERVICO_RISCO.calcular_risco()
            self._responder_json(200, resultado.to_dict())
            return

        # 3. API de Ativos (Requisito 2 - Lista JSON)
        if caminho == "/api/ativos":
            ativos = [ativo.to_dict() for ativo in REPO.listar_todos().values()]
            self._responder_json(200, {"total": len(ativos), "ativos": ativos})
            return

        # 4. Dashboard Web Visual (Root /)
        if caminho in ("/", "/index.html"):
            resultado = SERVICO_RISCO.calcular_risco()
            uptime_seg = int(time.time() - HORA_INICIO)
            uptime_str = f"{uptime_seg // 3600}h {(uptime_seg % 3600) // 60}m {uptime_seg % 60}s"

            linhas_tabela = ""
            for item in resultado.tabela_detalhada:
                deps_str = ", ".join(f"ID {k}: {v*100:.0f}%" for k, v in item.get("dependencias", {}).items()) or "Nenhuma"
                linhas_tabela += f"""
                <tr>
                    <td><strong>{item['id']}</strong></td>
                    <td>{item['hostname']}</td>
                    <td><span class="badge tipo">{item['tipo']}</span></td>
                    <td>{item['fator_exposicao']}x</td>
                    <td>{item['total_cves']} CVEs</td>
                    <td class="risco-proprio">{item['risco_proprio']:.2f}</td>
                    <td class="risco-efetivo"><strong>{item['risco_efetivo']:.2f}</strong></td>
                    <td class="deps">{deps_str}</td>
                </tr>
                """

            status_inv = "✅ Invertível (Estritamente Diagonal Dominante)" if resultado.invertivel else "❌ Não Invertível"

            html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UFU - Inventário e Análise de Risco | Container 24h</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #05070a;
            color: #e2e8f0;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: #0d131a;
            border: 1px solid #162b3d;
            border-radius: 12px;
            padding: 20px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }}
        h1 {{
            color: #38bdf8;
            font-size: 20px;
            margin: 0 0 6px 0;
        }}
        p.sub {{
            color: #94a3b8;
            margin: 0;
            font-size: 13px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge.up {{
            background: #064e3b;
            color: #34d399;
            border: 1px solid #059669;
        }}
        .badge.tipo {{
            background: #1e293b;
            color: #cbd5e1;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #0d131a;
            border: 1px solid #162b3d;
            border-radius: 10px;
            padding: 16px;
        }}
        .card h3 {{
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            margin: 0 0 8px 0;
        }}
        .card .valor {{
            font-size: 22px;
            font-weight: bold;
            color: #38bdf8;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #0d131a;
            border: 1px solid #162b3d;
            border-radius: 10px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid #162b3d;
            font-size: 13px;
        }}
        th {{
            background: #090d14;
            color: #38bdf8;
            font-weight: 600;
        }}
        tr:hover {{
            background: #111a24;
        }}
        .risco-proprio {{
            color: #fbbf24;
        }}
        .risco-efetivo {{
            color: #f87171;
            font-size: 14px;
        }}
        .deps {{
            color: #94a3b8;
            font-size: 12px;
        }}
        .footer {{
            margin-top: 24px;
            text-align: center;
            color: #64748b;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ UFU | Cibersegurança — Trabalho 02 (Sprints 3 a 5)</h1>
                <p class="sub">Aplicação de Inventário Orientada a Objetos em Execução no Container Docker</p>
            </div>
            <div>
                <span class="badge up">● CONTAINER 24H ONLINE</span>
            </div>
        </div>

        <div class="cards">
            <div class="card">
                <h3>Uptime Contínuo</h3>
                <div class="valor">{uptime_str}</div>
            </div>
            <div class="card">
                <h3>Total de Ativos (POO)</h3>
                <div class="valor">{len(resultado.tabela_detalhada)}</div>
            </div>
            <div class="card">
                <h3>Invertibilidade (I - A)</h3>
                <div class="valor" style="font-size: 14px; color: #34d399;">{status_inv}</div>
            </div>
            <div class="card">
                <h3>Determinante det(I - A)</h3>
                <div class="valor">{resultado.determinante:.4f}</div>
            </div>
        </div>

        <h2>📊 Modelo de Análise de Risco (Álgebra Linear: x = b + Ax)</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Hostname</th>
                    <th>Tipo (Subclasse)</th>
                    <th>Fator Exp.</th>
                    <th>CVEs</th>
                    <th>Risco Próprio (b)</th>
                    <th>Risco Efetivo (x)</th>
                    <th>Dependências (Matriz A)</th>
                </tr>
            </thead>
            <tbody>
                {linhas_tabela}
            </tbody>
        </table>

        <div class="footer">
            Universidade Federal de Uberlândia (UFU) • Bacharelado em Cibersegurança • Trabalho Avaliativo 02
        </div>
    </div>
</body>
</html>"""
            self._responder_html(200, html)
            return

        self._responder_json(404, {"erro": "Rota não encontrada", "rotas_disponiveis": ["/", "/api/health", "/api/risco", "/api/ativos"]})


class ServidorThreaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Servidor HTTP multithread para alta concorrência e estabilidade 24 horas."""
    daemon_threads = True
    allow_reuse_address = True


def iniciar_servidor():
    """Inicia o servidor e a thread de monitoramento contínuo com captura graciosa de sinais."""
    monitor = DaemonMonitorThread(intervalo_segundos=60)
    monitor.start()

    servidor = ServidorThreaded(("0.0.0.0", PORTA), InventarioHttpHandler)
    logging.info(f"🌐 Servidor HTTP ativo em http://0.0.0.0:{PORTA} (Pronto para operação contínua 24h)")

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
