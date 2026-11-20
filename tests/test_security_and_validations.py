import http.client
import json
import threading
import pytest

import app_server
from models import TipoAtivo
from repositories import JsonAtivoRepository
from services import auth_service
from services.asset_service import AssetService
from services.risco_service import RiscoLinearService


@pytest.fixture
def ambiente_auth_temp(tmp_path, monkeypatch):
    arquivo_usuarios = tmp_path / "usuarios.json"
    monkeypatch.setattr(auth_service, "NOME_ARQUIVO_USUARIOS", str(arquivo_usuarios))
    monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "AdminSegura123")
    auth_service.GERENCIADOR_SESSOES.limpar_tudo()
    auth_service.LIMITADOR_LOGIN.limpar_tudo()
    yield arquivo_usuarios
    auth_service.GERENCIADOR_SESSOES.limpar_tudo()
    auth_service.LIMITADOR_LOGIN.limpar_tudo()


@pytest.fixture
def servidor_teste(tmp_path, monkeypatch, ambiente_auth_temp):
    arquivo_ativos = tmp_path / "ativos.json"
    repo = JsonAtivoRepository(caminho_arquivo=str(arquivo_ativos))
    servico_ativos = AssetService(repositorio=repo)
    servico_risco = RiscoLinearService(repositorio=repo)

    monkeypatch.setattr(app_server, "REPO", repo)
    monkeypatch.setattr(app_server, "SERVICO_ATIVOS", servico_ativos)
    monkeypatch.setattr(app_server, "SERVICO_RISCO", servico_risco)

    servidor = app_server.ServidorThreaded(("127.0.0.1", 0), app_server.InventarioHttpHandler)
    porta = servidor.server_address[1]
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()

    yield porta

    servidor.shutdown()
    servidor.server_close()
    thread.join(timeout=2)


def _request(porta, metodo, caminho, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", porta, timeout=5)
    req_headers = dict(headers or {})
    payload = None
    if body is not None:
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        else:
            payload = body
    conn.request(metodo, caminho, body=payload, headers=req_headers)
    resp = conn.getresponse()
    raw = resp.read()
    resp_headers = dict(resp.getheaders())
    set_cookies = resp.headers.get_all("Set-Cookie") or []
    conn.close()
    try:
        dados = json.loads(raw.decode("utf-8"))
    except Exception:
        dados = raw.decode("utf-8", errors="replace")
    return resp.status, dados, resp_headers, set_cookies


def _extrair_cookie_sid(set_cookies):
    for header in set_cookies:
        for parte in header.split(";"):
            parte = parte.strip()
            if parte.startswith("sid="):
                return parte
    return ""


# --- Testes de Validação de Ativos e CVEs ---

def test_bloqueia_hostname_duplicado_case_insensitive_no_cadastro(servico_com_memoria):
    ok1, msg1 = servico_com_memoria.cadastrar_ativo(
        "201", "SRV-APP", "Carlos", "DC-1", TipoAtivo.SERVIDORES.value
    )
    assert ok1 is False
    assert "já existe" in msg1.lower()


def test_bloqueia_hostname_duplicado_na_atualizacao_mas_permite_proprio(servico_com_memoria):
    ok_duplicado, msg_dup = servico_com_memoria.atualizar_ativo(
        "102", "SRV-APP", "Carlos", "Rack 1", TipoAtivo.ROTEADORES_SWITCHES.value
    )
    assert ok_duplicado is False
    assert "já existe" in msg_dup.lower()

    ok_proprio, _ = servico_com_memoria.atualizar_ativo(
        "102", "sw-borda", "Carlos Silva", "Rack 2", TipoAtivo.ROTEADORES_SWITCHES.value
    )
    assert ok_proprio is True


def test_cve_duplicada_bloqueada_no_mesmo_ativo_e_permitida_em_outro(servico_com_memoria):
    ok_dup, msg_dup = servico_com_memoria.vincular_cve_ao_ativo("101", "cve-2021-44228")
    assert ok_dup is False
    assert "já está vinculada" in msg_dup.lower()

    ok_outro, _ = servico_com_memoria.vincular_cve_ao_ativo("102", "CVE-2021-44228")
    assert ok_outro is True

    ok_invalida, msg_inv = servico_com_memoria.vincular_cve_ao_ativo("102", "CVE-INVALIDA")
    assert ok_invalida is False
    assert "inválido" in msg_inv.lower()


def test_cadastro_rejeita_cve_duplicada_ou_invalida_no_payload(servico_com_memoria):
    ok_dup, msg_dup = servico_com_memoria.cadastrar_ativo(
        "301",
        "srv-novo-1",
        "Ana",
        "DC-1",
        TipoAtivo.SERVIDORES.value,
        vulnerabilidades=["CVE-2024-1234", "cve-2024-1234"],
    )
    assert ok_dup is False
    assert "duplicada" in msg_dup.lower()

    ok_inv, msg_inv = servico_com_memoria.cadastrar_ativo(
        "302",
        "srv-novo-2",
        "Ana",
        "DC-1",
        TipoAtivo.SERVIDORES.value,
        vulnerabilidades=["NAO-E-CVE"],
    )
    assert ok_inv is False
    assert "inválido" in msg_inv.lower()


def test_exclusao_ativo_limpa_dependencias_orfas(servico_com_memoria):
    ok_dep, _ = servico_com_memoria.adicionar_dependencia("101", "102", 0.3)
    assert ok_dep is True
    assert 102 in servico_com_memoria.obter_ativo(101).obter_dependencias()

    ok_del, _ = servico_com_memoria.deletar_ativo("102")
    assert ok_del is True
    assert 102 not in servico_com_memoria.obter_ativo(101).obter_dependencias()


# --- Testes de Autenticação e Usuários ---

def test_nao_sobrescreve_usuario_nem_duplica_nome(ambiente_auth_temp):
    auth_service.carregar_usuarios()

    ok_admin, msg_admin = auth_service.salvar_usuario("admin", "SenhaForte99", "Outro Admin", "admin")
    assert ok_admin is False
    assert "já está cadastrado" in msg_admin.lower()

    ok_user, _ = auth_service.salvar_usuario("operador1", "SenhaForte99", "Maria Silva", "user")
    assert ok_user is True

    ok_dup_nome, msg_nome = auth_service.salvar_usuario("operador2", "SenhaForte99", "maria silva", "user")
    assert ok_dup_nome is False
    assert "mesmo" in msg_nome.lower() or "já existe" in msg_nome.lower()

    ok_fraca, msg_fraca = auth_service.salvar_usuario("operador3", "123456", "Pedro Lima", "user")
    assert ok_fraca is False
    assert "8 caracteres" in msg_fraca.lower()


def test_compatibilidade_e_upgrade_hash_pbkdf2_legado(ambiente_auth_temp):
    hash_legado = auth_service.gerar_hash_senha("SenhaAntiga1", iteracoes=100_000)
    partes = hash_legado.split("$")
    formato_antigo = f"{partes[2]}${partes[3]}"

    assert auth_service.verificar_senha("SenhaAntiga1", formato_antigo) is True
    assert auth_service.verificar_senha("Errada123", formato_antigo) is False

    usuarios = auth_service.carregar_usuarios()
    usuarios["legado"] = {"hash": formato_antigo, "nome": "Usuario Legado", "role": "user"}
    auth_service._salvar_arquivo_usuarios(usuarios)

    ok, _ = auth_service.autenticar_usuario("legado", "SenhaAntiga1")
    assert ok is True

    atualizados = auth_service.carregar_usuarios()
    assert atualizados["legado"]["hash"].startswith(f"pbkdf2_sha256${auth_service.PBKDF2_ITERATIONS}$")


# --- Testes End-to-End HTTP de Segurança ---

def test_http_autenticacao_autorizacao_e_validacoes(servidor_teste):
    porta = servidor_teste

    # 1. Rotas protegidas exigem login
    status, _, headers, _ = _request(porta, "GET", "/api/ativos")
    assert status == 401
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "Access-Control-Allow-Origin" not in headers

    # 2. Health continua acessível (Docker healthcheck)
    status_h, dados_h, _, _ = _request(porta, "GET", "/api/health")
    assert status_h == 200
    assert dados_h["status"] == "UP"

    # 3. Login como admin gera cookie HttpOnly + SameSite=Strict
    status_l, dados_l, _, cookies = _request(
        porta, "POST", "/api/login", {"usuario": "admin", "senha": "AdminSegura123"}
    )
    assert status_l == 200
    assert dados_l["sucesso"] is True
    assert any("HttpOnly" in c and "SameSite=Strict" in c for c in cookies)
    cookie_admin = _extrair_cookie_sid(cookies)
    assert cookie_admin.startswith("sid=")

    # 4. Admin cria usuário comum
    status_u, _, _, _ = _request(
        porta,
        "POST",
        "/api/usuarios",
        {"usuario": "analista", "nome": "Ana Costa", "senha": "UserSegura123", "role": "user"},
        headers={"Cookie": cookie_admin},
    )
    assert status_u == 201

    # 5. Admin tenta duplicar usuário -> 409
    status_dup_u, _, _, _ = _request(
        porta,
        "POST",
        "/api/usuarios",
        {"usuario": "analista", "nome": "Outra Pessoa", "senha": "UserSegura123", "role": "user"},
        headers={"Cookie": cookie_admin},
    )
    assert status_dup_u == 409

    # 6. Login como usuário comum não pode acessar /api/usuarios -> 403
    status_lu, _, _, cookies_u = _request(
        porta, "POST", "/api/login", {"usuario": "analista", "senha": "UserSegura123"}
    )
    assert status_lu == 200
    cookie_user = _extrair_cookie_sid(cookies_u)

    status_forb, _, _, _ = _request(porta, "GET", "/api/usuarios", headers={"Cookie": cookie_user})
    assert status_forb == 403

    # 7. Cadastro de ativo + bloqueio de hostname duplicado (409) + bloqueio de CVE duplicada (409)
    st_cad1, _, _, _ = _request(
        porta,
        "POST",
        "/api/ativos",
        {
            "id_ativo": 10,
            "hostname": "srv-producao",
            "responsavel": "Ana",
            "localizacao": "DC-1",
            "tipo": "Servidores",
        },
        headers={"Cookie": cookie_user},
    )
    assert st_cad1 == 201

    st_cad_dup, _, _, _ = _request(
        porta,
        "POST",
        "/api/ativos",
        {
            "id_ativo": 11,
            "hostname": "SRV-PRODUCAO",
            "responsavel": "Ana",
            "localizacao": "DC-1",
            "tipo": "Servidores",
        },
        headers={"Cookie": cookie_user},
    )
    assert st_cad_dup == 409

    st_cve1, _, _, _ = _request(
        porta,
        "POST",
        "/api/ativos/10/cves",
        {"cve": "CVE-2021-44228"},
        headers={"Cookie": cookie_user},
    )
    assert st_cve1 == 200

    st_cve_dup, _, _, _ = _request(
        porta,
        "POST",
        "/api/ativos/10/cves",
        {"cve": "cve-2021-44228"},
        headers={"Cookie": cookie_user},
    )
    assert st_cve_dup == 409

    st_cve_inv, _, _, _ = _request(
        porta,
        "POST",
        "/api/ativos/10/cves",
        {"cve": "INVALIDA"},
        headers={"Cookie": cookie_user},
    )
    assert st_cve_inv == 400

    # 8. Logout invalida sessão
    st_out, _, _, _ = _request(porta, "POST", "/api/logout", headers={"Cookie": cookie_user})
    assert st_out == 200
    st_me, _, _, _ = _request(porta, "GET", "/api/me", headers={"Cookie": cookie_user})
    assert st_me == 401


def test_http_path_traversal_csp_payload_grande_e_rate_limit(servidor_teste):
    porta = servidor_teste

    # Path traversal bloqueado
    for ataque in ("/../usuarios.json", "/%2e%2e/usuarios.json", "/../app_server.py", "/..\\usuarios.json"):
        st, _, _, _ = _request(porta, "GET", ataque)
        assert st == 403

    # Index HTML entrega CSP estrita
    st_idx, _, headers_idx, _ = _request(porta, "GET", "/")
    assert st_idx == 200
    assert "script-src 'self'" in headers_idx.get("Content-Security-Policy", "")

    # Payload > 1MB bloqueado com 413
    st_big, _, _, _ = _request(
        porta,
        "POST",
        "/api/login",
        body=b"a",
        headers={"Content-Length": str(2 * 1024 * 1024), "Content-Type": "application/json"},
    )
    assert st_big == 413

    # Rate limit após 5 tentativas falhas -> 429 na 6ª
    for _ in range(5):
        st_fail, _, _, _ = _request(
            porta, "POST", "/api/login", {"usuario": "admin", "senha": "Errada123"}
        )
        assert st_fail == 401

    st_rl, _, headers_rl, _ = _request(
        porta, "POST", "/api/login", {"usuario": "admin", "senha": "AdminSegura123"}
    )
    assert st_rl == 429
    assert "Retry-After" in headers_rl
