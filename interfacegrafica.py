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

# Configuração do Tema 🌙
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ==========================================
# 📏 CONFIGURAÇÃO DE ESCALAMENTO (100% / Sem Zoom)
# ==========================================
ctk.set_widget_scaling(1.0)  # Resetado para 100%
ctk.set_window_scaling(1.0)

class TipoAtivo(Enum):
    SERVIDORES = "Servidores"
    ROTEADORES_SWITCHES = "Roteadores/Switches"
    COMPUTADORES = "Computadores"
    IMPRESSORAS = "Impressoras"

base_ativos = {}
NOME_ARQUIVO_ATIVOS = "base_ativos.json"
NOME_ARQUIVO_USUARIOS = "usuarios.json"

# ==========================================
# PALETA DE CORES 🎨
# ==========================================
COR_FUNDO = "#05070a"
COR_CARD = "#0d131a"
COR_BORDA = "#162b3d"
COR_AZUL_PRINCIPAL = "#0284c7"
COR_AZUL_HOVER = "#0369a1"
COR_VERDE_NEON = "#10b981"
COR_VERDE_HOVER = "#059669"
COR_TEXTO_DEST = "#38bdf8"
COR_TEXTO_VERDE = "#34d399"

# ==========================================
# 🛡️ SEGURANÇA E AUXILIARES
# ==========================================
def sanitizar_texto(texto):
    if not texto:
        return ""
    return re.sub(r'[<>\'\"\\\\;]', '', texto).strip()

def validar_cve(cve_texto):
    return bool(re.match(r'^CVE-\d{4}-\d{4,7}$', cve_texto.strip().upper()))

def validar_hostname(hostname):
    return bool(hostname and len(hostname) <= 63 and re.match(r'^[a-zA-Z0-9.-]+$', hostname))

def validar_id(id_str):
    if not id_str.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(id_str)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser entre 1 e 999999!"
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
            usuarios = json.load(f)
            if "admin" in usuarios and usuarios["admin"].get("role") != "admin":
                usuarios["admin"]["role"] = "admin"
                with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f_out:
                    json.dump(usuarios, f_out, indent=4, ensure_ascii=False)
            return usuarios
    except (FileNotFoundError, json.JSONDecodeError):
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
        self.geometry("400x480")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(False, False)

        self.card_login = ctk.CTkFrame(self, corner_radius=12, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        self.card_login.pack(padx=25, pady=30, fill="both", expand=True)

        ctk.CTkLabel(self.card_login, text="🛡️ UFU Cibersegurança", font=("Segoe UI", 18, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(20, 5))
        ctk.CTkLabel(self.card_login, text="Acesso Restrito ao Sistema", font=("Segoe UI", 12), text_color="#94a3b8").pack(pady=(0, 15))

        self.entry_usuario = ctk.CTkEntry(self.card_login, placeholder_text="Usuário (ex: admin)", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_usuario.pack(pady=8)

        self.entry_senha = ctk.CTkEntry(self.card_login, placeholder_text="Senha", show="•", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_senha.pack(pady=8)
        self.entry_senha.bind("<Return>", lambda event: self.func_efetuar_login())

        self.lbl_msg = ctk.CTkLabel(self.card_login, text="", font=("Segoe UI", 12, "bold"))
        self.lbl_msg.pack(pady=5)

        self.btn_entrar = ctk.CTkButton(self.card_login, text="Entrar no Sistema 🔓", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=280, command=self.func_efetuar_login)
        self.btn_entrar.pack(pady=12)

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

# ==========================================
# JANELA DE REGISTRO DE USUÁRIO (ADMIN) 👤
# ==========================================
class JanelaCadastroUsuario(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Cadastrar Novo Usuário (Admin)")
        self.geometry("400x480")
        self.configure(fg_color=COR_FUNDO)
        self.grab_set()

        card = ctk.CTkFrame(self, corner_radius=12, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(card, text="👤 Novo Usuário", font=("Segoe UI", 16, "bold"), text_color=COR_VERDE_NEON).pack(pady=15)

        self.entry_nome = ctk.CTkEntry(card, placeholder_text="Nome Completo", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_nome.pack(pady=6)

        self.entry_user = ctk.CTkEntry(card, placeholder_text="Nome de Usuário (login)", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_user.pack(pady=6)

        self.entry_pass = ctk.CTkEntry(card, placeholder_text="Senha", show="•", width=280, fg_color="#090d14", border_color=COR_BORDA)
        self.entry_pass.pack(pady=6)

        ctk.CTkLabel(card, text="Nível de Permissão:", font=("Segoe UI", 12, "bold"), text_color="#94a3b8").pack(pady=(6, 2))
        self.combo_role = ctk.CTkComboBox(card, values=["user", "admin"], width=280, fg_color="#090d14", button_color=COR_AZUL_PRINCIPAL)
        self.combo_role.set("user")
        self.combo_role.pack(pady=6)

        self.lbl_status = ctk.CTkLabel(card, text="", font=("Segoe UI", 12, "bold"))
        self.lbl_status.pack(pady=5)

        ctk.CTkButton(card, text="Salvar Usuário 💾", fg_color=COR_VERDE_NEON, hover_color=COR_VERDE_HOVER, text_color="#022c22", width=280, command=self.func_salvar_novo_usuario).pack(pady=15)

    def func_salvar_novo_usuario(self):
        nome = sanitizar_texto(self.entry_nome.get())
        user = self.entry_user.get().strip().lower()
        senha = self.entry_pass.get().strip()
        role = self.combo_role.get()

        if not nome or not user or not senha:
            self.lbl_status.configure(text="⚠️ Preencha todos os campos!", text_color="#facc15")
            return

        salvar_usuario(user, senha, nome, role)
        self.lbl_status.configure(text="✅ Usuário criado com sucesso!", text_color=COR_TEXTO_VERDE)
        
        if hasattr(self.master, "func_atualizar_lista_usuarios_adm"):
            self.master.func_atualizar_lista_usuarios_adm()

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
        self.geometry("850x700")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(True, True)

        carregar_dados_ativos()

        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color=COR_FUNDO, bg_color=COR_FUNDO)
        self.scroll_container.pack(fill="both", expand=True, padx=5, pady=5)

        self.header_frame = ctk.CTkFrame(self.scroll_container, corner_radius=10, fg_color=COR_CARD, border_width=1, border_color=COR_BORDA)
        self.header_frame.pack(pady=10, padx=10, fill="x")

        self.titulo = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ UFU - CIBERSEGURANÇA", 
            font=("Segoe UI", 18, "bold"),
            text_color=COR_TEXTO_DEST
        )
        self.titulo.pack(side="left", padx=15, pady=10)

        self.frame_top_right = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.frame_top_right.pack(side="right", padx=15)

        badge_color = COR_TEXTO_VERDE if self.role_logado == "admin" else "#94a3b8"
        ctk.CTkLabel(
            self.frame_top_right, 
            text=f"👤 {self.usuario_logado} ({self.role_logado.upper()})", 
            font=("Segoe UI", 12, "bold"), 
            text_color=badge_color
        ).pack(side="left", padx=(0, 10))

        self.btn_logout = ctk.CTkButton(
            self.frame_top_right,
            text="Sair 🚪",
            width=70,
            height=28,
            fg_color="#dc2626",
            hover_color="#991b1b",
            font=("Segoe UI", 11, "bold"),
            command=self.func_efetuar_logout
        )
        self.btn_logout.pack(side="left")

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
        self.tab_atualizar = self.tabview.add("✏️ Atualizar / Remover Ativo")
        self.tab_cve = self.tabview.add("⚠️ Vulnerabilidades")
        self.tab_relatorio = self.tabview.add("📊 Relatório & Busca")
        
        if self.role_logado == "admin":
            self.tab_admin = self.tabview.add("🔐 Gestão Usuários")
            self.setup_aba_admin()

        self.setup_aba_cadastrar()
        self.setup_aba_atualizar()
        self.setup_aba_cve()
        self.setup_aba_relatorio()

        self.lbl_status = ctk.CTkLabel(self.scroll_container, text=f"🔒 Sessão iniciada como '{self.usuario_logado}'.", font=("Segoe UI", 12, "bold"), text_color="#94a3b8")
        self.lbl_status.pack(pady=8)

        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    def func_efetuar_logout(self):
        self.destroy()
        login_screen = JanelaLogin(callback_sucesso=iniciar_aplicacao)
        login_screen.mainloop()

    # ==========================================
    # ABA EXCLUSIVA DE ADMIN
    # ==========================================
    def setup_aba_admin(self):
        frame_criar = ctk.CTkFrame(self.tab_admin, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_criar.pack(pady=(15, 5), padx=15, fill="x")

        ctk.CTkLabel(frame_criar, text="👤 Cadastrar Novo Usuário", font=("Segoe UI", 15, "bold"), text_color=COR_VERDE_NEON).pack(pady=(10, 4))
        
        ctk.CTkButton(
            frame_criar,
            text="Criar Usuário ➕",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            font=("Segoe UI", 12, "bold"),
            width=200,
            command=self.func_abrir_cadastro_admin
        ).pack(pady=10)

        frame_adm = ctk.CTkFrame(self.tab_admin, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_adm.pack(pady=10, padx=15, fill="x")

        ctk.CTkLabel(frame_adm, text="🔑 Alterar Permissão de Usuário Existente", font=("Segoe UI", 15, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(10, 4))

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
        ).pack(pady=10)

        self.func_atualizar_lista_usuarios_adm()

    def func_abrir_cadastro_admin(self):
        JanelaCadastroUsuario(self)

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
    # 1. CADASTRO DE NOVO ATIVO
    # ==========================================
    def setup_aba_cadastrar(self):
        frame_cad = ctk.CTkFrame(self.tab_cadastrar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_cad.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(frame_cad, text="➕ Novo Ativo no Inventário", font=("Segoe UI", 16, "bold"), text_color=COR_VERDE_NEON).pack(pady=(10, 4))

        self.cad_entry_id = ctk.CTkEntry(frame_cad, placeholder_text="ID / Tombamento Único (ex: 101)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_id.pack(pady=5)

        self.cad_entry_hostname = ctk.CTkEntry(frame_cad, placeholder_text="Hostname (ex: srv-db-01)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_hostname.pack(pady=5)

        self.cad_entry_responsavel = ctk.CTkEntry(frame_cad, placeholder_text="Responsável (ex: Ana Silva)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_responsavel.pack(pady=5)

        self.cad_entry_localizacao = ctk.CTkEntry(frame_cad, placeholder_text="Localização (ex: Data Center - Rack A)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.cad_entry_localizacao.pack(pady=5)

        ctk.CTkLabel(frame_cad, text="Tipo do Ativo:", font=("Segoe UI", 12, "bold"), text_color="#94a3b8").pack(pady=(4, 2))
        self.cad_combo_tipo = ctk.CTkComboBox(frame_cad, values=[t.value for t in TipoAtivo], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
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
        self.btn_cadastrar_ativo.pack(pady=12)

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
    # 2. ATUALIZAÇÃO E REMOÇÃO DE ATIVO
    # ==========================================
    def setup_aba_atualizar(self):
        frame_select = ctk.CTkFrame(self.tab_atualizar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_select.pack(pady=10, padx=15, fill="x")

        ctk.CTkLabel(frame_select, text="🔍 Selecionar Ativo Existente", font=("Segoe UI", 15, "bold"), text_color=COR_TEXTO_DEST).pack(pady=(8, 4))
        
        sub_select = ctk.CTkFrame(frame_select, fg_color="transparent")
        sub_select.pack(pady=(0, 8))

        self.upd_combo_selecionar = ctk.CTkOptionMenu(sub_select, values=["Nenhum ativo cadastrado"], width=250, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.upd_combo_selecionar.pack(side="left", padx=5)

        self.btn_carregar_ativo = ctk.CTkButton(sub_select, text="Carregar Dados 📥", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=140, command=self.func_carregar_dados_atualizacao)
        self.btn_carregar_ativo.pack(side="left", padx=5)

        frame_upd = ctk.CTkFrame(self.tab_atualizar, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_upd.pack(pady=5, padx=15, fill="x")

        self.upd_lbl_titulo = ctk.CTkLabel(frame_upd, text="Selecione um ativo acima para carregar", font=("Segoe UI", 13, "bold"), text_color="#94a3b8")
        self.upd_lbl_titulo.pack(pady=6)

        self.upd_entry_id = ctk.CTkEntry(frame_upd, placeholder_text="ID", width=320, fg_color="#101720", border_color=COR_BORDA, state="disabled")
        self.upd_entry_id.pack(pady=4)

        self.upd_entry_hostname = ctk.CTkEntry(frame_upd, placeholder_text="Hostname", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_hostname.pack(pady=4)

        self.upd_entry_responsavel = ctk.CTkEntry(frame_upd, placeholder_text="Responsável", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_responsavel.pack(pady=4)

        self.upd_entry_localizacao = ctk.CTkEntry(frame_upd, placeholder_text="Localização", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.upd_entry_localizacao.pack(pady=4)

        self.upd_combo_tipo = ctk.CTkComboBox(frame_upd, values=[t.value for t in TipoAtivo], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.upd_combo_tipo.pack(pady=4)

        # Botões de Ação (Atualizar e Remover)
        frame_acoes = ctk.CTkFrame(frame_upd, fg_color="transparent")
        frame_acoes.pack(pady=10)

        self.btn_salvar_atualizacao = ctk.CTkButton(
            frame_acoes, 
            text="Salvar Alterações 🔄", 
            fg_color=COR_AZUL_PRINCIPAL, 
            hover_color=COR_AZUL_HOVER, 
            font=("Segoe UI", 12, "bold"),
            width=170, 
            command=self.func_executar_atualizacao
        )
        self.btn_salvar_atualizacao.pack(side="left", padx=5)

        self.btn_deletar = ctk.CTkButton(
            frame_acoes, 
            text="Remover Ativo 🗑️", 
            fg_color="#dc2626", 
            hover_color="#991b1b", 
            font=("Segoe UI", 12, "bold"),
            width=150, 
            command=self.func_deletar_ativo_selecionado
        )
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

    def func_deletar_ativo_selecionado(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(text="⚠️ Selecione/carregue um ativo para remover!", text_color="#facc15")
            return

        valido, res_id = validar_id(id_str)
        if valido and res_id in base_ativos:
            del base_ativos[res_id]
            salvar_dados_ativos()
            
            self.lbl_status.configure(text=f"🗑️ Ativo {res_id} removido com sucesso!", text_color=COR_TEXTO_VERDE)
            
            # Limpa os campos
            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, 'end')
            self.upd_entry_id.configure(state="disabled")
            self.upd_entry_hostname.delete(0, 'end')
            self.upd_entry_responsavel.delete(0, 'end')
            self.upd_entry_localizacao.delete(0, 'end')
            self.upd_lbl_titulo.configure(text="Selecione um ativo acima para carregar", text_color="#94a3b8")

            self.func_atualizar_relatorio()
            self.func_atualizar_menu_selecao()

    # ==========================================
    # 3. GERENCIAMENTO DE CVE
    # ==========================================
    def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(self.tab_cve, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_cve.pack(pady=15, padx=20, fill="x")

        ctk.CTkLabel(frame_cve, text="Vincular Vulnerabilidade (CVE)", font=("Segoe UI", 16, "bold"), text_color="#f8fafc").pack(pady=10)

        self.entry_cve_id = ctk.CTkEntry(frame_cve, placeholder_text="ID do Ativo Alvo (ex: 101)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.entry_cve_id.pack(pady=5)

        self.entry_cve_cod = ctk.CTkEntry(frame_cve, placeholder_text="Código CVE (ex: CVE-2026-1042)", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.entry_cve_cod.pack(pady=5)

        ctk.CTkLabel(frame_cve, text="Severidade:", font=("Segoe UI", 12, "bold"), text_color="#94a3b8").pack(pady=(4, 2))
        self.combo_severidade = ctk.CTkComboBox(frame_cve, values=["Baixa", "Média", "Alta", "Crítica"], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_severidade.set("Alta")
        self.combo_severidade.pack(pady=4)

        ctk.CTkLabel(frame_cve, text="Status:", font=("Segoe UI", 12, "bold"), text_color="#94a3b8").pack(pady=(4, 2))
        self.combo_status_cve = ctk.CTkComboBox(frame_cve, values=["Identificada", "Em Análise", "Em Correção", "Mitigada", "Corrigida"], width=320, fg_color="#101720", button_color=COR_AZUL_PRINCIPAL)
        self.combo_status_cve.set("Identificada")
        self.combo_status_cve.pack(pady=4)

        self.btn_add_cve = ctk.CTkButton(frame_cve, text="Vincular CVE 🔗", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=200, command=self.func_adicionar_cve)
        self.btn_add_cve.pack(pady=12)

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

    # ==========================================
    # 4. RELATÓRIO E BUSCA
    # ==========================================
    def setup_aba_relatorio(self):
        frame_busca = ctk.CTkFrame(self.tab_relatorio, corner_radius=8, fg_color="#090d14", border_width=1, border_color=COR_BORDA)
        frame_busca.pack(pady=10, padx=15, fill="x")

        self.entry_busca = ctk.CTkEntry(frame_busca, placeholder_text="Filtrar por ID, Hostname ou Responsável...", width=320, fg_color="#101720", border_color=COR_BORDA)
        self.entry_busca.pack(side="left", padx=10, pady=8)
        self.entry_busca.bind("<KeyRelease>", lambda event: self.func_atualizar_relatorio())

        ctk.CTkButton(frame_busca, text="Atualizar 🔄", fg_color=COR_AZUL_PRINCIPAL, hover_color=COR_AZUL_HOVER, width=100, command=self.func_atualizar_relatorio).pack(side="left", padx=5)

        self.txt_relatorio = ctk.CTkTextbox(self.tab_relatorio, width=600, height=300, fg_color="#090d14", text_color="#e2e8f0", font=("Consolas", 12), border_width=1, border_color=COR_BORDA)
        self.txt_relatorio.pack(pady=10, padx=15, fill="both", expand=True)

    def func_atualizar_relatorio(self):
        self.txt_relatorio.delete("1.0", "end")
        termo = self.entry_busca.get().strip().lower()

        if not base_ativos:
            self.txt_relatorio.insert("end", "Nenhum ativo cadastrado na base de dados.\n")
            return

        encontrados = 0
        for id_ativo, dados in base_ativos.items():
            str_id = str(id_ativo)
            hostname = dados.get("hostname", "").lower()
            responsavel = dados.get("responsavel", "").lower()

            if termo and not (termo in str_id or termo in hostname or termo in responsavel):
                continue

            encontrados += 1
            info = f"📌 ID: {id_ativo} | Hostname: {dados.get('hostname')} | Tipo: {dados.get('tipo')}\n"
            info += f"   Responsável: {dados.get('responsavel')} | Local: {dados.get('localizacao')}\n"
            
            vulns = dados.get("vulnerabilidades", [])
            if vulns:
                info += "   ⚠️ Vulnerabilidades Registradas:\n"
                for v in vulns:
                    info += f"      - [{v.get('severidade')}] {v.get('cve')} | Status: {v.get('status')}\n"
            else:
                info += "   ✅ Nenhuma vulnerabilidade vinculada.\n"
            
            info += "-" * 65 + "\n"
            self.txt_relatorio.insert("end", info)

        if encontrados == 0:
            self.txt_relatorio.insert("end", "Nenhum resultado encontrado para a busca realizada.\n")

    def func_atualizar_menu_selecao(self):
        if not base_ativos:
            self.upd_combo_selecionar.configure(values=["Nenhum ativo cadastrado"])
            self.upd_combo_selecionar.set("Nenhum ativo cadastrado")
            return

        lista = [f"ID {k} - {v.get('hostname')}" for k, v in base_ativos.items()]
        self.upd_combo_selecionar.configure(values=lista)
        if lista:
            self.upd_combo_selecionar.set(lista[0])

# ==========================================
# INICIALIZAÇÃO DA APLICAÇÃO 🚀
# ==========================================
def iniciar_aplicacao(usuario, role):
    app = AplicacaoInventario(usuario_logado=usuario, role_logado=role)
    app.mainloop()

if __name__ == "__main__":
    app_login = JanelaLogin(callback_sucesso=iniciar_aplicacao)
    app_login.mainloop()