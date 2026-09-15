import json
import os
import sys
import io
import re
import hashlib
import secrets
from enum import Enum
import customtkinter as ctk

# Configuração para terminal do Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Configuração do Tema 🌙 (Dark Mode - Preto, Verde e Azul)
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class TipoAtivo(Enum):
    SERVIDORES = "Servidores"
    ROTEADORES_SWITCHES = "Roteadores/Switches"
    COMPUTADORES = "Computadores"
    IMPRESSORAS = "Impressoras"

base_ativos = {}
NOME_ARQUIVO_ATIVOS = "base_ativos.json"
NOME_ARQUIVO_USUARIOS = "usuarios.json"

# ==========================================
# PALETA DE CORES (PRETO, VERDE E AZUL) 🎨
# ==========================================
COR_FUNDO = "#05070a"         # Preto Cyber Profundo
COR_CARD = "#0d131a"          # Azul/Preto Escuro para cards
COR_BORDA = "#162b3d"         # Borda Azul Escuro
COR_AZUL_PRINCIPAL = "#0284c7" # Azul Cibersegurança
COR_AZUL_HOVER = "#0369a1"
COR_VERDE_NEON = "#10b981"    # Verde Destaque/Sucesso
COR_VERDE_HOVER = "#059669"
COR_TEXTO_DEST = "#38bdf8"    # Cyan/Azul Claro para destaques
COR_TEXTO_VERDE = "#34d399"   # Verde Claro para destaques

# ==========================================
# 🛡️ SEGURANÇA: SANITIZAÇÃO E CRIPTOGRAFIA
# ==========================================
def sanitizar_texto(texto):
    if not texto:
        return ""
    texto_limpo = re.sub(r'[<>\'\"\\\\;]', '', texto)
    return texto_limpo.strip()

def validar_cve(cve_texto):
    cve_limpo = cve_texto.strip().upper()
    padrao_cve = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(padrao_cve, cve_limpo))

def validar_hostname(hostname):
    if not hostname or len(hostname) > 63:
        return False
    padrao_hostname = r'^[a-zA-Z0-9.-]+$'
    return bool(re.match(padrao_hostname, hostname))

def validar_id(id_str):
    if not id_str.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(id_str)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser um número entre 1 e 999999!"
    return True, val

def gerar_hash_senha(senha, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verificar_senha(senha_digitada, hash_salvo):
    try:
        salt, key_hex = hash_salvo.split('$')
        novo_hash = hashlib.pbkdf2_hmac('sha256', senha_digitada.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return secrets.compare_digest(novo_hash, key_hex)
    except Exception:
        return False

# ==========================================
# PERSISTÊNCIA DE DADOS 💾
# ==========================================
def salvar_dados_ativos():
    try:
        dados = {str(k): v for k, v in base_ativos.items()}
        with open(NOME_ARQUIVO_ATIVOS, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar ativos: {e}")
        return False

def carregar_dados_ativos():
    global base_ativos
    try:
        with open(NOME_ARQUIVO_ATIVOS, "r", encoding="utf-8") as f:
            base_ativos = {int(k): v for k, v in json.load(f).items()}
    except (FileNotFoundError, json.JSONDecodeError):
        base_ativos = {}

def carregar_usuarios():
    try:
        with open(NOME_ARQUIVO_USUARIOS, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Admin inicial recebe 'role': 'admin'
        usuarios_iniciais = {
            "admin": {
                "hash": gerar_hash_senha("admin123"),
                "nome": "Administrador UFU",
                "role": "admin"
            }
        }
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios_iniciais, f, indent=4, ensure_ascii=False)
        return usuarios_iniciais

def salvar_usuario(usuario, senha, nome, role="user"):
    usuarios = carregar_usuarios()
    usuarios[usuario] = {
        "hash": gerar_hash_senha(senha),
        "nome": nome,
        "role": role
    }
    with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=4, ensure_ascii=False)

def atualizar_role_usuario(usuario, novo_role):
    usuarios = carregar_usuarios()
    if usuario in usuarios:
        usuarios[usuario]["role"] = novo_role
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
        return True
    return False

# ==========================================
# TELA DE LOGIN 🔐
# ==========================================
class JanelaLogin(ctk.CTk):
    def __init__(self, callback_sucesso):
        super().__init__()
        self.callback_sucesso = callback_sucesso

        self.title("UFU - Autenticação")
        self.geometry("420x520")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(False, False)

        self.card_login = ctk.CTkFrame(self, corner_radius=12, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        self.card_login.pack(padx=30, pady=40, fill="both", expand=True)

        ctk.CTkLabel(self.card_login, text="🛡️ UFU Cibersegurança", font=("Segoe UI", 18, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(25, 5))
        ctk.CTkLabel(self.card_login, text="Acesso Restrito ao Sistema", font=("Segoe UI", 11), text_color="#94a3b8").pack(pady=(0, 20))

        self.entry_usuario = ctk.CTkEntry(self.card_login, placeholder_text="Usuário (ex: admin)", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_usuario.pack(pady=8)

        self.entry_senha = ctk.CTkEntry(self.card_login, placeholder_text="Senha", show="•", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_senha.pack(pady=8)
        self.entry_senha.bind("<Return>", lambda event: self.func_efetuar_login())

        self.lbl_msg = ctk.CTkLabel(self.card_login, text="", font=("Segoe UI", 11, "bold"))
        self.lbl_msg.pack(pady=5)

        self.btn_entrar = ctk.CTkButton(self.card_login, text="Entrar no Sistema 🔓", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=280, command=self.func_efetuar_login)
        self.btn_entrar.pack(pady=12)

        self.btn_cadastrar = ctk.CTkButton(self.card_login, text="Criar Novo Usuário 👤", fg_color=COR_VERDE_NEON, hover_color=COR_VERDE_HOVER, text_color="#022c22", width=280, command=self.func_abrir_cadastro)
        self.btn_cadastrar.pack(pady=4)

    def func_efetuar_login(self):
        usuario = self.entry_usuario.get().strip().lower()
        senha = self.entry_senha.get().strip()
        usuarios = carregar_usuarios()

        if usuario in usuarios and verificar_senha(senha, usuarios[usuario]["hash"]):
            dados_user = usuarios[usuario]
            nome_usuario = dados_user.get("nome", usuario)
            role_usuario = dados_user.get("role", "user")
            
            self.destroy()
            self.callback_sucesso(nome_usuario, role_usuario)
        else:
            self.lbl_msg.configure(text="❌ Usuário ou senha incorretos!", text_color="#ef4444")

    def func_abrir_cadastro(self):
        JanelaCadastroUsuario(self)

# ==========================================
# JANELA DE REGISTRO DE USUÁRIO 👤
# ==========================================
class JanelaCadastroUsuario(ctk.CTkToplevel):
    def __init__(self, parent, eh_admin=False):
        super().__init__(parent)
        self.eh_admin = eh_admin
        self.title("Cadastrar Novo Usuário")
        self.geometry("380x500")
        self.configure(fg_color=COR_FUNDO)
        self.grab_set()

        card = ctk.CTkFrame(self, corner_radius=12, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(card, text="👤 Novo Usuário", font=("Segoe UI", 16, "bold"), text_color=COR_VERDE_NEON).pack(pady=15)

        self.entry_nome = ctk.CTkEntry(card, placeholder_text="Nome Completo", width=260, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_nome.pack(pady=6)

        self.entry_user = ctk.CTkEntry(card, placeholder_text="Nome de Usuário (login)", width=260, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_user.pack(pady=6)

        self.entry_pass = ctk.CTkEntry(card, placeholder_text="Senha", show="•", width=260, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_pass.pack(pady=6)

        # Seleção de Permissão (habilitada apenas para administradores)
        ctk.CTkLabel(card, text="Nível de Permissão:", font=("Segoe UI", 11, "bold"), text_color="#94a3b8").pack(pady=(6, 2))
        self.combo_role = ctk.CTkComboBox(card, values=["user", "admin"], width=260, fg_color="#090d14", button_color=COR_AZUL_PRINCIPAL)
        self.combo_role.set("user")
        
        if not self.eh_admin:
            self.combo_role.configure(state="disabled")

        self.combo_role.pack(pady=6)

        self.lbl_status = ctk.CTkLabel(card, text="", font=("Segoe UI", 11, "bold"))
        self.lbl_status.pack(pady=5)

        ctk.CTkButton(card, text="Salvar Usuário 💾", fg_color=COR_VERDE_NEON, hover_color=COR_VERDE_HOVER, text_color="#022c22", width=260, command=self.func_salvar_novo_usuario).pack(pady=15)

    def func_salvar_novo_usuario(self):
        nome = sanitizar_texto(self.entry_nome.get())
        user = self.entry_user.get().strip().lower()
        senha = self.entry_pass.get().strip()
        role = self.combo_role.get() if self.eh_admin else "user"

        if not nome or not user or not senha:
            self.lbl_status.configure(text="⚠️ Preencha todos os campos!", text_color="#facc15")
            return

        usuarios = carregar_usuarios()
        if user in usuarios:
            self.lbl_status.configure(text="❌ Este usuário já existe!", text_color="#ef4444")
            return

        salvar_usuario(user, senha, nome, role)
        self.lbl_status.configure(text="✅ Usuário criado com sucesso!", text_color=COR_TEXTO_VERDE)
        self.after(1200, self.destroy)

# ==========================================
# INTERFACE PRINCIPAL DO SISTEMA 🖥️
# ==========================================
class AplicacaoInventario(ctk.CTk):
    def __init__(self, usuario_logado, role_logado):
        super().__init__()
        self.usuario_logado = usuario_logado
        self.role_logado = role_logado

        self.title("UFU - CIBERSEGURANÇA 🔒")
        self.geometry("780x860")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(True, True)
        self.minsize(680, 600)

        carregar_dados_ativos()

        # Container Principal com Rolagem
        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color=COR_FUNDO, bg_color=COR_FUNDO)
        self.scroll_container.pack(fill="both", expand=True, padx=5, pady=5)

        # Cabeçalho
        self.header_frame = ctk.CTkFrame(self.scroll_container, corner_radius=10, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        self.header_frame.pack(pady=10, padx=10, fill="x")

        self.titulo = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ UFU - CIBERSEGURANÇA", 
            font=("Segoe UI", 18, "bold"),
            text_color=COR_TEXTO_DEST
        )
        self.titulo.pack(side="left", padx=15, pady=12)

        # Controle Topo: Usuário, Role, Logout e Zoom
        self.frame_top_right = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.frame_top_right.pack(side="right", padx=15)

        badge_color = COR_TEXTO_VERDE if self.role_logado == "admin" else "#94a3b8"
        ctk.CTkLabel(
            self.frame_top_right, 
            text=f"👤 {self.usuario_logado} ({self.role_logado.upper()})", 
            font=("Segoe UI", 11, "bold"), 
            text_color=badge_color
        ).pack(side="left", padx=(0, 10))

        # 🚪 BOTÃO DE LOGOUT
        self.btn_logout = ctk.CTkButton(
            self.frame_top_right,
            text="Sair 🚪",
            width=65,
            height=28,
            fg_color="#dc2626",
            hover_color="#991b1b",
            font=("Segoe UI", 11, "bold"),
            command=self.func_efetuar_logout
        )
        self.btn_logout.pack(side="left", padx=(0, 15))

        ctk.CTkLabel(self.frame_top_right, text="Zoom:", font=("Segoe UI", 11, "bold"), text_color="#94a3b8").pack(side="left", padx=(0, 5))
        
        self.combo_zoom = ctk.CTkOptionMenu(
            self.frame_top_right,
            values=["80%", "100%", "125%", "150%"],
            width=85,
            fg_color="#090d14",
            button_color=COR_AZUL_PRINCIPAL,
            command=self.func_mudar_escala
        )
        self.combo_zoom.set("100%")
        self.combo_zoom.pack(side="left")

        # Sistema de Abas
        self.tabview = ctk.CTkTabview(
            self.scroll_container, 
            corner_radius=10, 
            fg_color=COR_CARD, 
            segmented_button_fg_color="#090d14", 
            segmented_button_selected_color=COR_AZUL_PRINCIPAL,
            segmented_button_selected_hover_color=COR_AZUL_HOVER
        )
        self.tabview.pack(pady=5, padx=10, fill="both", expand=True)

        self.tab_cadastrar = self.tabview.add("➕ Novo Ativo")
        self.tab_atualizar = self.tabview.add("✏️ Atualizar Ativo")
        self.tab_cve = self.tabview.add("⚠️ Vulnerabilidades")
        self.tab_relatorio = self.tabview.add("📊 Relatório & Busca")
        
        # Aba exclusiva para Administradores
        if self.role_logado == "admin":
            self.tab_admin = self.tabview.add("🔐 Gestão Usuários")
            self.setup_aba_admin()

        self.setup_aba_cadastrar()
        self.setup_aba_atualizar()
        self.setup_aba_cve()
        self.setup_aba_relatorio()

        self.lbl_status = ctk.CTkLabel(self.scroll_container, text=f"🔒 Sessão iniciada como '{self.usuario_logado}'.", font=("Segoe UI", 11, "bold"), text_color="#94a3b8")
        self.lbl_status.pack(pady=8)

        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    def func_efetuar_logout(self):
        """Fecha a aplicação principal e reabre a tela de login."""
        self.destroy()
        login_screen = JanelaLogin(callback_sucesso=iniciar_aplicacao)
        login_screen.mainloop()

    def func_mudar_escala(self, valor_selecionado):
        escala_map = {"80%": 0.8, "100%": 1.0, "125%": 1.25, "150%": 1.5}
        ctk.set_widget_scaling(escala_map.get(valor_selecionado, 1.0))
        self.lbl_status.configure(text=f"🔍 Proporção alterada para {valor_selecionado}.", text_color=COR_TEXTO_DEST)

    # ==========================================
    # ABA EXCLUSIVA DE ADMIN (GESTÃO DE ACESSO)
    # ==========================================
    def setup_aba_admin(self):
        frame_adm = ctk.CTkFrame(self.tab_admin, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_adm.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(frame_adm, text="🔑 Atribuir Permissões de Usuário", font=("Segoe UI", 15, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(12, 4))

        self.combo_usuarios_adm = ctk.CTkOptionMenu(frame_adm, values=["Carregando..."], width=300, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_usuarios_adm.pack(pady=6)

        self.combo_role_adm = ctk.CTkComboBox(frame_adm, values=["user", "admin"], width=300, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_role_adm.pack(pady=6)

        ctk.CTkButton(
            frame_adm,
            text="Atualizar Permissão 🔄",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=200,
            command=self.func_alterar_permissao
        ).pack(pady=12)

        self.func_atualizar_lista_usuarios_adm()

    def func_atualizar_lista_usuarios_adm(self):
        usuarios = carregar_usuarios()
        lista = [f"{u} ({d.get('role', 'user')})" for u, d in usuarios.items()]
        self.combo_usuarios_adm.configure(values=lista)
        if lista:
            self.combo_usuarios_adm.set(lista[0])

    def func_alterar_permissao(self):
        item = self.combo_usuarios_adm.get()
        if not item or "(" not in item:
            return
        
        usuario_alvo = item.split(" ")[0]
        novo_role = self.combo_role_adm.get()

        if atualizar_role_usuario(usuario_alvo, novo_role):
            self.lbl_status.configure(text=f"✅ Permissão de '{usuario_alvo}' alterada para '{novo_role}'.", text_color=COR_TEXTO_VERDE)
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.lbl_status.configure(text="❌ Falha ao alterar permissão.", text_color="#ef4444")

    # ==========================================
    # 1. ABA DE CADASTRO DE NOVO ATIVO (CREATE)
    # ==========================================
    def setup_aba_cadastrar(self):
        frame_cad = ctk.CTkFrame(self.tab_cadastrar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_cad.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(frame_cad, text="➕ Novo Ativo no Inventário", font=("Segoe UI", 15, "bold"), text_color=COR_VERDE_NEON).pack(pady=(12, 4))
        ctk.CTkLabel(frame_cad, text="Preencha os dados do novo patrimônio. O ID deve ser único.", font=("Segoe UI", 11), text_color="#94a3b8").pack(pady=(0, 10))

        self.cad_entry_id = ctk.CTkEntry(frame_cad, placeholder_text="ID / Tombamento Único (ex: 101)", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_id.pack(pady=6)

        self.cad_entry_hostname = ctk.CTkEntry(frame_cad, placeholder_text="Hostname (ex: srv-db-01)", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_hostname.pack(pady=6)

        self.cad_entry_responsavel = ctk.CTkEntry(frame_cad, placeholder_text="Responsável (ex: Ana Silva)", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_responsavel.pack(pady=6)

        self.cad_entry_localizacao = ctk.CTkEntry(frame_cad, placeholder_text="Localização (ex: Data Center - Rack A)", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_localizacao.pack(pady=6)

        ctk.CTkLabel(frame_cad, text="Tipo do Ativo:", font=("Segoe UI", 11, "bold"), text_color="#94a3b8").pack(pady=(4, 2))
        self.cad_combo_tipo = ctk.CTkComboBox(frame_cad, values=[t.value for t in TipoAtivo], width=350, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.cad_combo_tipo.pack(pady=4)

        self.btn_cadastrar_ativo = ctk.CTkButton(
            frame_cad, 
            text="Cadastrar Novo Ativo ➕", 
            fg_color=COR_VERDE_NEON, 
            hover_color=COR_VERDE_HOVER, 
            text_color="#022c22", 
            font=("Segoe UI", 12, "bold"),
            width=220,
            command=self.func_executar_cadastro
        )
        self.btn_cadastrar_ativo.pack(pady=15)

    def func_executar_cadastro(self):
        valido, res_id = validar_id(self.cad_entry_id.get().strip())
        if not valido:
            self.lbl_status.configure(text=f"🛡️ Erro de Validação: {res_id}", text_color="#ef4444")
            return

        if res_id in base_ativos:
            self.lbl_status.configure(text=f"❌ Erro: O ID {res_id} já existe!", text_color="#ef4444")
            return

        hostname_bruto = self.cad_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(text="🛡️ Erro: Hostname inválido!", text_color="#ef4444")
            return

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.cad_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.cad_entry_localizacao.get()),
            "tipo": self.cad_combo_tipo.get(),
            "vulnerabilidades": []
        }

        salvar_dados_ativos()
        self.lbl_status.configure(text=f"✅ Novo Ativo {res_id} registrado com sucesso!", text_color=COR_TEXTO_VERDE)
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()
        
        self.cad_entry_id.delete(0, 'end')
        self.cad_entry_hostname.delete(0, 'end')
        self.cad_entry_responsavel.delete(0, 'end')
        self.cad_entry_localizacao.delete(0, 'end')

    # ==========================================
    # 2. ABA DE ATUALIZAÇÃO DE ATIVO (UPDATE)
    # ==========================================
    def setup_aba_atualizar(self):
        frame_select = ctk.CTkFrame(self.tab_atualizar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_select.pack(pady=10, padx=15, fill="x")

        ctk.CTkLabel(frame_select, text="🔍 Selecionar Ativo Existente", font=("Segoe UI", 13, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(8, 4))
        
        sub_select = ctk.CTkFrame(frame_select, fg_color="transparent")
        sub_select.pack(pady=(0, 8))

        self.upd_combo_selecionar = ctk.CTkOptionMenu(sub_select, values=["Nenhum ativo cadastrado"], width=240, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.upd_combo_selecionar.pack(side="left", padx=5)

        self.btn_carregar_ativo = ctk.CTkButton(sub_select, text="Carregar Dados 📥", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=130, command=self.func_carregar_dados_atualizacao)
        self.btn_carregar_ativo.pack(side="left", padx=5)

        frame_upd = ctk.CTkFrame(self.tab_atualizar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_upd.pack(pady=5, padx=15, fill="x")

        self.upd_lbl_titulo = ctk.CTkLabel(frame_upd, text="Selecione um ativo acima para carregar", font=("Segoe UI", 13, "bold"), text_color="#94a3b8")
        self.upd_lbl_titulo.pack(pady=8)

        self.upd_entry_id = ctk.CTkEntry(frame_upd, placeholder_text="ID (Bloqueado p/ Edição)", width=350, fg_color="#101720", border_color=COR_BORDA, state="disabled")
        self.upd_entry_id.pack(pady=4)

        self.upd_entry_hostname = ctk.CTkEntry(frame_upd, placeholder_text="Hostname", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_hostname.pack(pady=4)

        self.upd_entry_responsavel = ctk.CTkEntry(frame_upd, placeholder_text="Responsável", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_responsavel.pack(pady=4)

        self.upd_entry_localizacao = ctk.CTkEntry(frame_upd, placeholder_text="Localização", width=350, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_localizacao.pack(pady=4)

        self.upd_combo_tipo = ctk.CTkComboBox(frame_upd, values=[t.value for t in TipoAtivo], width=350, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.upd_combo_tipo.pack(pady=4)

        self.btn_salvar_atualizacao = ctk.CTkButton(
            frame_upd, 
            text="Salvar Alterações 🔄", 
            fg_color=COR_AZUL_PRINCIPAL, 
            hover_color=COR_AZUL_HOVER, 
            font=("Segoe UI", 12, "bold"),
            width=220, 
            command=self.func_executar_atualizacao
        )
        self.btn_salvar_atualizacao.pack(pady=12)

        # Exclusão protegida por role de Administrador
        if self.role_logado == "admin":
            frame_del = ctk.CTkFrame(self.tab_atualizar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
            frame_del.pack(pady=10, padx=15, fill="x")

            ctk.CTkLabel(frame_del, text="Excluir Ativo da Base (Apenas Admin)", font=("Segoe UI", 12, "bold"), text_color="#f87171").pack(pady=4)

            sub_frame_del = ctk.CTkFrame(frame_del, fg_color="transparent")
            sub_frame_del.pack(pady=4)

            self.entry_del_id = ctk.CTkEntry(sub_frame_del, placeholder_text="ID p/ remover", width=160, fg_color="#101720", border_color=COR_BORDA)
            self.entry_del_id.pack(side="left", padx=5)

            self.btn_deletar = ctk.CTkButton(sub_frame_del, text="Remover 🗑️", fg_color="#dc2626", hover_color="#991b1b", width=120, command=self.func_deletar_ativo)
            self.btn_deletar.pack(side="left", padx=5)

    def func_carregar_dados_atualizacao(self):
        item = self.upd_combo_selecionar.get()
        if item == "Nenhum ativo cadastrado" or not item:
            self.lbl_status.configure(text="⚠️ Selecione um ativo válido!", text_color="#facc15")
            return
        try:
            id_val = int(item.split(" ")[1])
        except (IndexError, ValueError):
            return

        if id_val in base_ativos:
            ativo = base_ativos[id_val]
            
            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, 'end')
            self.upd_entry_id.insert(0, str(id_val))
            self.upd_entry_id.configure(state="disabled")

            self.upd_entry_hostname.delete(0, 'end')
            self.upd_entry_hostname.insert(0, ativo.get("hostname", ""))

            self.upd_entry_responsavel.delete(0, 'end')
            self.upd_entry_responsavel.insert(0, ativo.get("responsavel", ""))

            self.upd_entry_localizacao.delete(0, 'end')
            self.upd_entry_localizacao.insert(0, ativo.get("localizacao", ""))

            self.upd_combo_tipo.set(ativo.get("tipo", TipoAtivo.SERVIDORES.value))

            self.upd_lbl_titulo.configure(text=f"✏️ Editando Ativo ID: {id_val}", text_color=COR_TEXTO_DEST)
            self.lbl_status.configure(text=f"📥 Dados do Ativo {id_val} carregados.", text_color=COR_TEXTO_DEST)

    def func_executar_atualizacao(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(text="⚠️ Selecione um ativo para editar!", text_color="#facc15")
            return

        valido, res_id = validar_id(id_str)
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(text="❌ O ativo informado não existe!", text_color="#ef4444")
            return

        hostname_bruto = self.upd_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(text="🛡️ Erro: Hostname inválido!", text_color="#ef4444")
            return

        vulnerabilidades_existentes = base_ativos[res_id].get("vulnerabilidades", [])

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.upd_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.upd_entry_localizacao.get()),
            "tipo": self.upd_combo_tipo.get(),
            "vulnerabilidades": vulnerabilidades_existentes
        }

        salvar_dados_ativos()
        self.lbl_status.configure(text=f"✅ Ativo {res_id} atualizado com sucesso!", text_color=COR_TEXTO_VERDE)
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    # ==========================================
    # 3. ABA DE GERENCIAMENTO DE CVE
    # ==========================================
    def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(self.tab_cve, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_cve.pack(pady=15, padx=20, fill="x")

        ctk.CTkLabel(frame_cve, text="Vincular Vulnerabilidade (CVE)", font=("Segoe UI", 14, "bold"), text_color="#f8fafc").pack(pady=10)

        self.entry_cve_id = ctk.CTkEntry(frame_cve, placeholder_text="ID do Ativo Alvo (ex: 101)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.entry_cve_id.pack(pady=6)

        self.entry_cve_cod = ctk.CTkEntry(frame_cve, placeholder_text="Código CVE (ex: CVE-2026-1042)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.entry_cve_cod.pack(pady=6)

        ctk.CTkLabel(frame_cve, text="Severidade da Vulnerabilidade:", font=("Segoe UI", 11, "bold"), text_color="#94a3b8").pack(pady=(6, 2))
        self.combo_severidade = ctk.CTkComboBox(frame_cve, values=["Baixa", "Média", "Alta", "Crítica"], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_severidade.set("Alta")
        self.combo_severidade.pack(pady=4)

        ctk.CTkLabel(frame_cve, text="Status da Vulnerabilidade:", font=("Segoe UI", 11, "bold"), text_color="#94a3b8").pack(pady=(6, 2))
        self.combo_status_cve = ctk.CTkComboBox(frame_cve, values=["Identificada", "Em Análise", "Em Correção", "Mitigada", "Corrigida"], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_status_cve.set("Identificada")
        self.combo_status_cve.pack(pady=4)

        self.btn_add_cve = ctk.CTkButton(frame_cve, text="Vincular CVE 🔗", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=200, command=self.func_adicionar_cve)
        self.btn_add_cve.pack(pady=15)

    def func_adicionar_cve(self):
        valido, res_id = validar_id(self.entry_cve_id.get().strip())
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(text="⚠️ Ativo não encontrado!", text_color="#facc15")
            return

        cve_cod = self.entry_cve_cod.get().strip().upper()
        if not validar_cve(cve_cod):
            self.lbl_status.configure(text="🛡️ Erro: CVE inválida (ex: CVE-2026-1042)", text_color="#ef4444")
            return

        base_ativos[res_id]["vulnerabilidades"].append({
            "cve": cve_cod,
            "severidade": self.combo_severidade.get(),
            "status": self.combo_status_cve.get()
        })
        salvar_dados_ativos()
        self.lbl_status.configure(text=f"✅ CVE '{cve_cod}' vinculada ao Ativo {res_id}!", text_color=COR_TEXTO_VERDE)
        self.func_atualizar_relatorio()
        self.entry_cve_id.delete(0, 'end')
        self.entry_cve_cod.delete(0, 'end')

    def func_deletar_ativo(self):
        if self.role_logado != "admin":
            self.lbl_status.configure(text="⛔ Apenas administradores podem excluir ativos!", text_color="#ef4444")
            return

        valido, res_id = validar_id(self.entry_del_id.get().strip())
        if valido and res_id in base_ativos:
            del base_ativos[res_id]
            salvar_dados_ativos()
            self.lbl_status.configure(text=f"🗑️ Ativo {res_id} removido da base!", text_color=COR_TEXTO_VERDE)
            self.func_atualizar_relatorio()
            self.func_atualizar_menu_selecao()
            self.entry_del_id.delete(0, 'end')
            
            if self.upd_entry_id.get() == str(res_id):
                self.upd_entry_id.configure(state="normal")
                self.upd_entry_id.delete(0, 'end')
                self.upd_entry_id.configure(state="disabled")
                self.upd_entry_hostname.delete(0, 'end')
                self.upd_entry_responsavel.delete(0, 'end')
                self.upd_entry_localizacao.delete(0, 'end')
                self.upd_lbl_titulo.configure(text="Selecione um ativo acima para carregar", text_color="#94a3b8")
        else:
            self.lbl_status.configure(text="⚠️ Ativo não encontrado!", text_color="#facc15")

    # ==========================================
    # 4. ABA DE RELATÓRIO E BUSCA
    # ==========================================
    def setup_aba_relatorio(self):
        self.frame_cards = ctk.CTkFrame(self.tab_relatorio, fg_color="transparent")
        self.frame_cards.pack(pady=5, fill="x")

        self.card_ativos = ctk.CTkLabel(self.frame_cards, text="Ativos: 0", font=("Segoe UI", 12, "bold"), fg_color="#090d14", text_color=COR_TEXTO_DEST, corner_radius=6, width=150, height=30)
        self.card_ativos.pack(side="left", padx=10, expand=True)

        self.card_cves = ctk.CTkLabel(self.frame_cards, text="CVEs: 0", font=("Segoe UI", 12, "bold"), fg_color="#090d14", text_color=COR_TEXTO_VERDE, corner_radius=6, width=150, height=30)
        self.card_cves.pack(side="right", padx=10, expand=True)

        frame_busca = ctk.CTkFrame(self.tab_relatorio, fg_color="transparent")
        frame_busca.pack(pady=5, padx=5, fill="x")

        self.entry_busca = ctk.CTkEntry(frame_busca, placeholder_text="🔍 Buscar por ID, Hostname, Resp., Local ou CVE...", width=380, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_busca.pack(side="left", padx=(0, 5), expand=True, fill="x")
        self.entry_busca.bind("<KeyRelease>", lambda event: self.func_buscar_ativos())

        self.btn_limpar_busca = ctk.CTkButton(frame_busca, text="Limpar ✖", width=90, fg_color="#1e293b", hover_color="#334155", command=self.func_limpar_busca)
        self.btn_limpar_busca.pack(side="right")

        self.caixa_relatorio = ctk.CTkTextbox(self.tab_relatorio, height=350, font=("Consolas", 12), fg_color="#060a0f", text_color="#e2e8f0", border_width=1, border_color=COR_BORDA)
        self.caixa_relatorio.pack(pady=5, padx=5, fill="both", expand=True)
        self.caixa_relatorio.configure(state="disabled")

    def func_atualizar_menu_selecao(self):
        opcoes = ["Nenhum ativo cadastrado"] if not base_ativos else [f"ID {k} - {v['hostname']}" for k, v in base_ativos.items()]
        self.upd_combo_selecionar.configure(values=opcoes)
        self.upd_combo_selecionar.set(opcoes[0])

    def func_buscar_ativos(self):
        termo = sanitizar_texto(self.entry_busca.get()).lower()
        if not termo:
            self.func_atualizar_relatorio()
            return

        self.caixa_relatorio.configure(state="normal")
        self.caixa_relatorio.delete("1.0", ctk.END)
        encontrados = 0
        total_cves_filtro = 0

        for id_ativo, ativo in base_ativos.items():
            cves_str = " ".join([v['cve'].lower() for v in ativo.get('vulnerabilidades', [])])
            if termo in str(id_ativo).lower() or termo in ativo['hostname'].lower() or termo in ativo['responsavel'].lower() or termo in cves_str:
                encontrados += 1
                qtd_v = len(ativo.get('vulnerabilidades', []))
                total_cves_filtro += qtd_v

                texto = f"🆔 ID: {id_ativo} | 💻 Hostname: {ativo['hostname']}\n"
                texto += f"🏷️ Tipo: {ativo['tipo']} | 👤 Resp: {ativo['responsavel']} | 📍 Local: {ativo['localizacao']}\n"
                if ativo['vulnerabilidades']:
                    texto += f"⚠️ Vulnerabilidades ({qtd_v}):\n"
                    for v in ativo['vulnerabilidades']:
                        texto += f"   • {v['cve']} | Severidade: {v['severidade']} | Status: {v['status']}\n"
                else:
                    texto += "✅ Sem vulnerabilidades associadas.\n"
                texto += "─" * 60 + "\n"
                self.caixa_relatorio.insert(ctk.END, texto)

        self.card_ativos.configure(text=f"Exibindo: {encontrados}/{len(base_ativos)}")
        self.card_cves.configure(text=f"CVEs no Filtro: {total_cves_filtro}")
        self.caixa_relatorio.configure(state="disabled")

    def func_limpar_busca(self):
        self.entry_busca.delete(0, 'end')
        self.func_atualizar_relatorio()

    def func_atualizar_relatorio(self):
        self.caixa_relatorio.configure(state="normal")
        self.caixa_relatorio.delete("1.0", ctk.END)
        total_cves = 0

        for id_ativo, ativo in base_ativos.items():
            qtd_v = len(ativo.get('vulnerabilidades', []))
            total_cves += qtd_v

            texto = f"🆔 ID: {id_ativo} | 💻 Hostname: {ativo['hostname']}\n"
            texto += f"🏷️ Tipo: {ativo['tipo']} | 👤 Resp: {ativo['responsavel']} | 📍 Local: {ativo['localizacao']}\n"
            if ativo['vulnerabilidades']:
                texto += f"⚠️ Vulnerabilidades ({qtd_v}):\n"
                for v in ativo['vulnerabilidades']:
                    texto += f"   • {v['cve']} | Severidade: {v['severidade']} | Status: {v['status']}\n"
            else:
                texto += "✅ Sem vulnerabilidades associadas.\n"
            texto += "─" * 60 + "\n"
            self.caixa_relatorio.insert(ctk.END, texto)

        self.card_ativos.configure(text=f"Ativos: {len(base_ativos)}")
        self.card_cves.configure(text=f"CVEs: {total_cves}")
        self.caixa_relatorio.configure(state="disabled")


# ==========================================
# INICIALIZAÇÃO DO SISTEMA
# ==========================================
def iniciar_aplicacao(nome_usuario, role_usuario):
    app = AplicacaoInventario(usuario_logado=nome_usuario, role_logado=role_usuario)
    app.mainloop()

if __name__ == "__main__":
    login_screen = JanelaLogin(callback_sucesso=iniciar_aplicacao)
    login_screen.mainloop()
