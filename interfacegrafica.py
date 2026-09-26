import hashlib
import io
import json
import os
import re
import secrets
import sys
from enum import Enum
import customtkinter as ctk
from deep_translator import GoogleTranslator
import requests
from tkinter import messagebox, ttk

# Configuração para o terminal do Windows 🪟
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# Configuração do Tema 🌙
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ==========================================
# 📏 CONFIGURAÇÃO DE ESCALAMENTO (100% / Sem Zoom)
# ==========================================
ctk.set_widget_scaling(1.0)
ctk.set_window_scaling(1.0)


class TipoAtivo(Enum):
    SERVIDORES = "Servidores"
    ROTEADORES_SWITCHES = "Roteadores/Switches"
    COMPUTADORES = "Computadores"
    IMPRESSORAS = "Impressoras"


base_ativos = {}
NOME_ARQUIVO_ATIVOS = "base_ativos.json"
NOME_ARQUIVO_USUARIOS = "usuarios.json"
NOME_ARQUIVO_CVES = "cves_salvas.json"

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
    return re.sub(r'[<>\'\"\\\\;]', "", texto).strip()


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


def gerar_hash_senha(senha, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt.encode("utf-8"), 100000
    )
    return f"{salt}${key.hex()}"


def verificar_senha(senha_digitada, hash_salvo):
    try:
        salt, key_hex = hash_salvo.split("$")
        novo_hash = hashlib.pbkdf2_hmac(
            "sha256", senha_digitada.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()
        return secrets.compare_digest(novo_hash, key_hex)
    except Exception:
        return False


def traduzir_texto(texto_ingles):
    if not texto_ingles:
        return "Descrição não disponível."
    try:
        return GoogleTranslator(source="en", target="pt").translate(
            texto_ingles
        )
    except Exception:
        return texto_ingles


# ==========================================
# 💾 PERSISTÊNCIA E CACHE DE CVES LOCAL
# ==========================================
def carregar_cves_locais():
    if not os.path.exists(NOME_ARQUIVO_CVES):
        return {}
    try:
        with open(NOME_ARQUIVO_CVES, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def guardar_cve_local(codigo_cve, dados_cve):
    dados_locais = carregar_cves_locais()
    dados_locais[codigo_cve] = dados_cve
    try:
        with open(NOME_ARQUIVO_CVES, "w", encoding="utf-8") as f:
            json.dump(dados_locais, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar cache da CVE: {e}")
        return False


# ==========================================
# 🚦 TRADUTOR DE SEVERIDADE DE CVE
# ==========================================
def traduzir_severidade(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return (
                "🚨 CRÍTICO (Ação Urgente!)",
                "#ef4444",
                "💡 Ação Recomendada: Aplicar patch de segurança IMEDIATAMENTE e isolar o ativo se possível.",
            )
        elif score >= 7.0:
            return (
                "⚠️ ALTO (Atenção Prioritária)",
                "#f97316",
                "💡 Ação Recomendada: Agendar atualização do software o quanto antes.",
            )
        elif score >= 4.0:
            return (
                "🟡 MÉDIO (Planejar Correção)",
                "#eab308",
                "💡 Ação Recomendada: Corrigir na próxima janela de manutenção programada.",
            )
        else:
            return (
                "🟢 BAIXO (Risco Reduzido)",
                "#10b981",
                "💡 Ação Recomendada: Monitorar o ativo; correção opcional.",
            )
    except ValueError:
        return (
            "❓ Desconhecido / Não Avaliado",
            "#94a3b8",
            "💡 Ação Recomendada: Consultar a documentação do fornecedor do software.",
        )


# ==========================================
# 🌐 INTEGRAÇÃO COM API NVD/NIST + CACHE + TRADUÇÃO
# ==========================================
def consultar_cve_nvd(codigo_cve):
    codigo_limpo = codigo_cve.strip().upper()

    if not validar_cve(codigo_limpo):
        return {
            "erro": "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)"
        }

    cves_locais = carregar_cves_locais()
    if codigo_limpo in cves_locais:
        dados_cache = cves_locais[codigo_limpo]
        dados_cache["origem"] = "local"
        return dados_cache

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={codigo_limpo}"
    headers = {"User-Agent": "MeuAppPython/1.0"}

    try:
        resposta = requests.get(url, headers=headers, timeout=10)
        if resposta.status_code == 200:
            dados = resposta.json()
            vulnerabilidades = dados.get("vulnerabilities", [])

            if not vulnerabilidades:
                return {
                    "erro": "Vulnerabilidade não encontrada na base de dados oficial da NVD."
                }

            cve_data = vulnerabilidades[0].get("cve", {})

            descriptions = cve_data.get("descriptions", [])
            descricao_en = "Descrição não disponível."
            for d in descriptions:
                if d.get("lang") == "en":
                    descricao_en = d.get("value")
                    break

            metrics = cve_data.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [])
            cvss_score = (
                cvss_data[0].get("cvssData", {}).get("baseScore", "N/A")
                if cvss_data
                else "N/A"
            )

            descricao_pt = traduzir_texto(descricao_en)

            estrutura_cve = {
                "id": codigo_limpo,
                "cvss": cvss_score,
                "descricao_en": descricao_en,
                "descricao": descricao_pt,
                "origem": "api",
            }

            guardar_cve_local(codigo_limpo, estrutura_cve)

            return estrutura_cve
        else:
            return {
                "erro": f"Erro na resposta da NVD. Código HTTP: {resposta.status_code}"
            }
    except Exception as e:
        return {"erro": f"Falha na conexão com a NVD: {e}"}


# ==========================================
# PERSISTÊNCIA DE DADOS DOS ATIVOS 💾
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
            if (
                "admin" in usuarios
                and usuarios["admin"].get("role") != "admin"
            ):
                usuarios["admin"]["role"] = "admin"
                with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f_out:
                    json.dump(usuarios, f_out, indent=4, ensure_ascii=False)
            return usuarios
    except (FileNotFoundError, json.JSONDecodeError):
        usuarios_iniciais = {
            "admin": {
                "hash": gerar_hash_senha("admin123"),
                "nome": "Administrador UFU",
                "role": "admin",
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
        "role": role,
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


def deletar_usuario(usuario):
    if usuario.lower() == "admin":
        return False, "O usuário 'admin' padrão não pode ser removido!"

    usuarios = carregar_usuarios()
    if usuario in usuarios:
        del usuarios[usuario]
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
        return True, f"Usuário '{usuario}' removido com sucesso!"
    return False, "Usuário não encontrado."


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

        self.card_login = ctk.CTkFrame(
            self,
            corner_radius=12,
            fg_color=COR_CARD,
            border_width=1,
            border_color=COR_BORDA,
        )
        self.card_login.pack(padx=25, pady=30, fill="both", expand=True)

        ctk.CTkLabel(
            self.card_login,
            text="🛡️ UFU Cibersegurança",
            font=("Segoe UI", 18, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(20, 5))
        ctk.CTkLabel(
            self.card_login,
            text="Acesso Restrito ao Sistema",
            font=("Segoe UI", 12),
            text_color="#94a3b8",
        ).pack(pady=(0, 15))

        self.entry_usuario = ctk.CTkEntry(
            self.card_login,
            placeholder_text="Usuário (ex: admin)",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_usuario.pack(pady=8)

        self.entry_senha = ctk.CTkEntry(
            self.card_login,
            placeholder_text="Senha",
            show="•",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_senha.pack(pady=8)
        self.entry_senha.bind(
            "<Return>", lambda event: self.func_efetuar_login()
        )

        self.lbl_msg = ctk.CTkLabel(
            self.card_login, text="", font=("Segoe UI", 12, "bold")
        )
        self.lbl_msg.pack(pady=5)

        self.btn_entrar = ctk.CTkButton(
            self.card_login,
            text="Entrar no Sistema 🔓",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=280,
            command=self.func_efetuar_login,
        )
        self.btn_entrar.pack(pady=12)

    def func_efetuar_login(self):
        usuario = self.entry_usuario.get().strip().lower()
        senha = self.entry_senha.get().strip()
        usuarios = carregar_usuarios()

        if usuario in usuarios and verificar_senha(
            senha, usuarios[usuario]["hash"]
        ):
            dados_user = usuarios[usuario]
            nome_usuario = dados_user.get("nome", usuario)
            role_usuario = dados_user.get("role", "user")

            self.destroy()
            self.callback_sucesso(nome_usuario, role_usuario, usuario)
        else:
            self.lbl_msg.configure(
                text="❌ Usuário ou senha incorretos!", text_color="#ef4444"
            )


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

        card = ctk.CTkFrame(
            self,
            corner_radius=12,
            fg_color=COR_CARD,
            border_width=1,
            border_color=COR_BORDA,
        )
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(
            card,
            text="👤 Novo Usuário",
            font=("Segoe UI", 16, "bold"),
            text_color=COR_VERDE_NEON,
        ).pack(pady=15)

        self.entry_nome = ctk.CTkEntry(
            card,
            placeholder_text="Nome Completo",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_nome.pack(pady=6)

        self.entry_user = ctk.CTkEntry(
            card,
            placeholder_text="Nome de Usuário (login)",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_user.pack(pady=6)

        self.entry_pass = ctk.CTkEntry(
            card,
            placeholder_text="Senha",
            show="•",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_pass.pack(pady=6)

        ctk.CTkLabel(
            card,
            text="Nível de Permissão:",
            font=("Segoe UI", 12, "bold"),
            text_color="#94a3b8",
        ).pack(pady=(6, 2))
        self.combo_role = ctk.CTkComboBox(
            card,
            values=["user", "admin"],
            width=280,
            fg_color="#090d14",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.combo_role.set("user")
        self.combo_role.pack(pady=6)

        self.lbl_status = ctk.CTkLabel(
            card, text="", font=("Segoe UI", 12, "bold")
        )
        self.lbl_status.pack(pady=5)

        ctk.CTkButton(
            card,
            text="Salvar Usuário 💾",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            width=280,
            command=self.func_salvar_novo_usuario,
        ).pack(pady=15)

    def func_salvar_novo_usuario(self):
        nome = sanitizar_texto(self.entry_nome.get())
        user = self.entry_user.get().strip().lower()
        senha = self.entry_pass.get().strip()
        role = self.combo_role.get()

        if not nome or not user or not senha:
            self.lbl_status.configure(
                text="⚠️ Preencha todos os campos!", text_color="#facc15"
            )
            return

        salvar_usuario(user, senha, nome, role)
        self.lbl_status.configure(
            text="✅ Usuário criado com sucesso!", text_color=COR_TEXTO_VERDE
        )

        if hasattr(self.master, "func_atualizar_lista_usuarios_adm"):
            self.master.func_atualizar_lista_usuarios_adm()

        self.after(1200, self.destroy)


# ==========================================
# INTERFACE PRINCIPAL DO SISTEMA 🖥️
# ==========================================
class AplicacaoInventario(ctk.CTk):

    def __init__(self, usuario_logado, role_logado, login_id):
        super().__init__()
        self.usuario_logado = usuario_logado
        self.role_logado = role_logado
        self.login_id = login_id

        self.title("UFU - CIBERSEGURANÇA 🔒")
        self.geometry("900x780")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(True, True)

        carregar_dados_ativos()

        self.scroll_container = ctk.CTkScrollableFrame(
            self, fg_color=COR_FUNDO, bg_color=COR_FUNDO
        )
        self.scroll_container.pack(fill="both", expand=True, padx=5, pady=5)

        self.header_frame = ctk.CTkFrame(
            self.scroll_container,
            corner_radius=10,
            fg_color=COR_CARD,
            border_width=1,
            border_color=COR_BORDA,
        )
        self.header_frame.pack(pady=10, padx=10, fill="x")

        self.titulo = ctk.CTkLabel(
            self.header_frame,
            text="🛡️ UFU - CIBERSEGURANÇA",
            font=("Segoe UI", 18, "bold"),
            text_color=COR_TEXTO_DEST,
        )
        self.titulo.pack(side="left", padx=15, pady=10)

        self.frame_top_right = ctk.CTkFrame(
            self.header_frame, fg_color="transparent"
        )
        self.frame_top_right.pack(side="right", padx=15)

        badge_color = (
            COR_TEXTO_VERDE if self.role_logado == "admin" else "#94a3b8"
        )
        ctk.CTkLabel(
            self.frame_top_right,
            text=f"👤 {self.usuario_logado} ({self.role_logado.upper()})",
            font=("Segoe UI", 12, "bold"),
            text_color=badge_color,
        ).pack(side="left", padx=(0, 10))

        self.btn_alterar_senha = ctk.CTkButton(
            self.frame_top_right,
            text="Alterar Senha 🔑",
            width=110,
            height=28,
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            font=("Segoe UI", 11, "bold"),
            command=self.abrir_janela_alterar_senha,
        )
        self.btn_alterar_senha.pack(side="left", padx=(0, 8))

        self.btn_logout = ctk.CTkButton(
            self.frame_top_right,
            text="Sair 🚪",
            width=70,
            height=28,
            fg_color="#dc2626",
            hover_color="#991b1b",
            font=("Segoe UI", 11, "bold"),
            command=self.func_efetuar_logout,
        )
        self.btn_logout.pack(side="left")

        self.tabview = ctk.CTkTabview(
            self.scroll_container,
            corner_radius=10,
            fg_color=COR_CARD,
            segmented_button_fg_color="#090d14",
            segmented_button_selected_color=COR_AZUL_PRINCIPAL,
            segmented_button_selected_hover_color=COR_AZUL_HOVER,
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

        self.lbl_status = ctk.CTkLabel(
            self.scroll_container,
            text=f"🔒 Sessão iniciada como '{self.usuario_logado}'.",
            font=("Segoe UI", 12, "bold"),
            text_color="#94a3b8",
        )
        self.lbl_status.pack(pady=8)

        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    def func_efetuar_logout(self):
        self.destroy()
        iniciar_aplicacao()

    # ==========================================
    # ALTERAÇÃO DE PALAVRA-PASSE 🔑
    # ==========================================
    def abrir_janela_alterar_senha(self):
        self.janela_senha = ctk.CTkToplevel(self)
        self.janela_senha.title("Alterar Palavra-Passe")
        self.janela_senha.geometry("380x320")
        self.janela_senha.configure(fg_color=COR_FUNDO)
        self.janela_senha.grab_set()

        card = ctk.CTkFrame(
            self.janela_senha,
            corner_radius=12,
            fg_color=COR_CARD,
            border_width=1,
            border_color=COR_BORDA,
        )
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(
            card,
            text="🔑 Alterar Palavra-Passe",
            font=("Segoe UI", 16, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=12)

        self.entry_senha_atual = ctk.CTkEntry(
            card,
            placeholder_text="Senha Atual",
            show="•",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_senha_atual.pack(pady=6)

        self.entry_nova_senha = ctk.CTkEntry(
            card,
            placeholder_text="Nova Senha",
            show="•",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_nova_senha.pack(pady=6)

        self.entry_confirma_senha = ctk.CTkEntry(
            card,
            placeholder_text="Confirmar Nova Senha",
            show="•",
            width=280,
            fg_color="#090d14",
            border_color=COR_BORDA,
        )
        self.entry_confirma_senha.pack(pady=6)

        ctk.CTkButton(
            card,
            text="Salvar Nova Senha 💾",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            width=280,
            command=self.func_confirmar_alteracao_senha,
        ).pack(pady=15)

    def func_confirmar_alteracao_senha(self):
        atual = self.entry_senha_atual.get().strip()
        nova = self.entry_nova_senha.get().strip()
        confirma = self.entry_confirma_senha.get().strip()

        if not atual or not nova or not confirma:
            messagebox.showerror("Erro ⚠️", "Preencha todos os campos!")
            return

        usuarios = carregar_usuarios()
        if self.login_id not in usuarios:
            messagebox.showerror("Erro ⚠️", "Usuário não encontrado!")
            return

        if not verificar_senha(atual, usuarios[self.login_id]["hash"]):
            messagebox.showerror("Erro ⚠️", "Senha atual incorreta!")
            return

        if nova != confirma:
            messagebox.showerror(
                "Erro ⚠️", "A nova senha e a confirmação não coincidem!"
            )
            return

        if len(nova) < 6:
            messagebox.showwarning(
                "Aviso 🛡️", "A nova senha deve ter pelo menos 6 caracteres."
            )
            return

        usuarios[self.login_id]["hash"] = gerar_hash_senha(nova)
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)

        messagebox.showinfo("Sucesso ✅", "Senha alterada com sucesso!")
        self.janela_senha.destroy()

    # ==========================================
    # ABA EXCLUSIVA DE ADMIN
    # ==========================================
    def setup_aba_admin(self):
        frame_criar = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_criar.pack(pady=(10, 5), padx=15, fill="x")

        ctk.CTkLabel(
            frame_criar,
            text="👤 Cadastrar Novo Usuário",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_VERDE_NEON,
        ).pack(pady=(8, 4))
        ctk.CTkButton(
            frame_criar,
            text="Criar Usuário ➕",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            font=("Segoe UI", 12, "bold"),
            width=200,
            command=self.func_abrir_cadastro_admin,
        ).pack(pady=8)

        frame_adm = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_adm.pack(pady=5, padx=15, fill="x")

        ctk.CTkLabel(
            frame_adm,
            text="🔑 Alterar Permissão de Usuário",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(8, 4))

        self.combo_usuarios_adm = ctk.CTkOptionMenu(
            frame_adm,
            values=["Carregando..."],
            width=280,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.combo_usuarios_adm.pack(pady=4)

        self.combo_role_adm = ctk.CTkComboBox(
            frame_adm,
            values=["user", "admin"],
            width=280,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.combo_role_adm.pack(pady=4)

        ctk.CTkButton(
            frame_adm,
            text="Atualizar Permissão 🔄",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=200,
            command=self.func_alterar_permissao,
        ).pack(pady=8)

        frame_del_usr = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_del_usr.pack(pady=5, padx=15, fill="x")

        ctk.CTkLabel(
            frame_del_usr,
            text="🗑️ Remover Usuário Cadastrado",
            font=("Segoe UI", 15, "bold"),
            text_color="#f87171",
        ).pack(pady=(8, 4))

        self.combo_del_usuario = ctk.CTkOptionMenu(
            frame_del_usr,
            values=["Carregando..."],
            width=280,
            fg_color="#101720",
            button_color="#dc2626",
        )
        self.combo_del_usuario.pack(pady=4)

        ctk.CTkButton(
            frame_del_usr,
            text="Excluir Usuário ❌",
            fg_color="#dc2626",
            hover_color="#991b1b",
            width=200,
            command=self.func_remover_usuario,
        ).pack(pady=8)

        self.func_atualizar_lista_usuarios_adm()

    def func_abrir_cadastro_admin(self):
        JanelaCadastroUsuario(self)

    def func_atualizar_lista_usuarios_adm(self):
        usuarios = carregar_usuarios()
        lista = [f"{u} ({d.get('role', 'user')})" for u, d in usuarios.items()]

        self.combo_usuarios_adm.configure(values=lista)
        if lista:
            self.combo_usuarios_adm.set(lista[0])

        lista_puros = list(usuarios.keys())
        self.combo_del_usuario.configure(values=lista_puros)
        if lista_puros:
            self.combo_del_usuario.set(lista_puros[0])

    def func_alterar_permissao(self):
        item = self.combo_usuarios_adm.get()
        if not item or "(" not in item:
            return

        usuario_alvo = item.split(" ")[0]
        novo_role = self.combo_role_adm.get()

        if atualizar_role_usuario(usuario_alvo, novo_role):
            self.lbl_status.configure(
                text=f"✅ Permissão de '{usuario_alvo}' alterada para '{novo_role}'.",
                text_color=COR_TEXTO_VERDE,
            )
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.lbl_status.configure(
                text="❌ Falha ao alterar permissão.", text_color="#ef4444"
            )

    def func_remover_usuario(self):
        usuario_alvo = self.combo_del_usuario.get()
        if not usuario_alvo:
            return

        sucesso, msg = deletar_usuario(usuario_alvo)
        if sucesso:
            self.lbl_status.configure(
                text=f"✅ {msg}", text_color=COR_TEXTO_VERDE
            )
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.lbl_status.configure(text=f"❌ {msg}", text_color="#ef4444")

    # ==========================================
    #  CADASTRO DE NOVO ATIVO
    # ==========================================
    def setup_aba_cadastrar(self):
        frame_cad = ctk.CTkFrame(
            self.tab_cadastrar,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_cad.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(
            frame_cad,
            text="➕ Novo Ativo no Inventário",
            font=("Segoe UI", 16, "bold"),
            text_color=COR_VERDE_NEON,
        ).pack(pady=(10, 4))

        self.cad_entry_id = ctk.CTkEntry(
            frame_cad,
            placeholder_text="ID / Tombamento Único (ex: 101)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cad_entry_id.pack(pady=5)

        self.cad_entry_hostname = ctk.CTkEntry(
            frame_cad,
            placeholder_text="Hostname (ex: srv-db-01)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cad_entry_hostname.pack(pady=5)

        self.cad_entry_responsavel = ctk.CTkEntry(
            frame_cad,
            placeholder_text="Responsável (ex: Ana Silva)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cad_entry_responsavel.pack(pady=5)

        self.cad_entry_localizacao = ctk.CTkEntry(
            frame_cad,
            placeholder_text="Localização (ex: Data Center - Rack A)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cad_entry_localizacao.pack(pady=5)

        ctk.CTkLabel(
            frame_cad,
            text="Tipo do Ativo:",
            font=("Segoe UI", 12, "bold"),
            text_color="#94a3b8",
        ).pack(pady=(4, 2))
        self.cad_combo_tipo = ctk.CTkComboBox(
            frame_cad,
            values=[t.value for t in TipoAtivo],
            width=320,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.cad_combo_tipo.pack(pady=4)

        self.btn_cadastrar_ativo = ctk.CTkButton(
            frame_cad,
            text="Cadastrar Novo Ativo ➕",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            font=("Segoe UI", 12, "bold"),
            width=220,
            command=self.func_executar_cadastro,
        )
        self.btn_cadastrar_ativo.pack(pady=12)

    def func_executar_cadastro(self):
        valido, res_id = validar_id(self.cad_entry_id.get().strip())
        if not valido:
            self.lbl_status.configure(
                text=f"🛡️ Erro de Validação: {res_id}", text_color="#ef4444"
            )
            return

        if res_id in base_ativos:
            self.lbl_status.configure(
                text=f"❌ Erro: O ID {res_id} já existe!", text_color="#ef4444"
            )
            return

        hostname_bruto = self.cad_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(
                text="🛡️ Erro: Hostname inválido!", text_color="#ef4444"
            )
            return

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.cad_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.cad_entry_localizacao.get()),
            "tipo": self.cad_combo_tipo.get(),
            "vulnerabilidades": [],
        }

        salvar_dados_ativos()
        self.lbl_status.configure(
            text=f"✅ Novo Ativo {res_id} registrado com sucesso!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

        self.cad_entry_id.delete(0, "end")
        self.cad_entry_hostname.delete(0, "end")
        self.cad_entry_responsavel.delete(0, "end")
        self.cad_entry_localizacao.delete(0, "end")

    # ==========================================
    #  ATUALIZAÇÃO E REMOÇÃO DE ATIVO
    # ==========================================
    def setup_aba_atualizar(self):
        frame_select = ctk.CTkFrame(
            self.tab_atualizar,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_select.pack(pady=10, padx=15, fill="x")

        ctk.CTkLabel(
            frame_select,
            text="🔍 Selecionar Ativo Existente",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(8, 4))

        sub_select = ctk.CTkFrame(frame_select, fg_color="transparent")
        sub_select.pack(pady=(0, 8))

        self.upd_combo_selecionar = ctk.CTkOptionMenu(
            sub_select,
            values=["Nenhum ativo cadastrado"],
            width=250,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.upd_combo_selecionar.pack(side="left", padx=5)

        self.btn_carregar_ativo = ctk.CTkButton(
            sub_select,
            text="Carregar Dados 📥",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=140,
            command=self.func_carregar_dados_atualizacao,
        )
        self.btn_carregar_ativo.pack(side="left", padx=5)

        frame_upd = ctk.CTkFrame(
            self.tab_atualizar,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_upd.pack(pady=5, padx=15, fill="x")

        self.upd_lbl_titulo = ctk.CTkLabel(
            frame_upd,
            text="Selecione um ativo acima para carregar",
            font=("Segoe UI", 13, "bold"),
            text_color="#94a3b8",
        )
        self.upd_lbl_titulo.pack(pady=6)

        self.upd_entry_id = ctk.CTkEntry(
            frame_upd,
            placeholder_text="ID",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
            state="disabled",
        )
        self.upd_entry_id.pack(pady=4)

        self.upd_entry_hostname = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Hostname",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_hostname.pack(pady=4)

        self.upd_entry_responsavel = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Responsável",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_responsavel.pack(pady=4)

        self.upd_entry_localizacao = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Localização",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_localizacao.pack(pady=4)

        self.upd_combo_tipo = ctk.CTkComboBox(
            frame_upd,
            values=[t.value for t in TipoAtivo],
            width=320,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.upd_combo_tipo.pack(pady=4)

        frame_acoes = ctk.CTkFrame(frame_upd, fg_color="transparent")
        frame_acoes.pack(pady=10)

        self.btn_salvar_atualizacao = ctk.CTkButton(
            frame_acoes,
            text="Salvar Alterações 🔄",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            font=("Segoe UI", 12, "bold"),
            width=170,
            command=self.func_executar_atualizacao,
        )
        self.btn_salvar_atualizacao.pack(side="left", padx=5)

        self.btn_deletar = ctk.CTkButton(
            frame_acoes,
            text="Remover Ativo 🗑️",
            fg_color="#dc2626",
            hover_color="#991b1b",
            font=("Segoe UI", 12, "bold"),
            width=150,
            command=self.func_deletar_ativo_selecionado,
        )
        self.btn_deletar.pack(side="left", padx=5)

    def func_atualizar_menu_selecao(self):
        if not hasattr(self, "upd_combo_selecionar"):
            return
        lista = [
            f"ID: {k} - {v.get('hostname', '')}" for k, v in base_ativos.items()
        ]
        if not lista:
            lista = ["Nenhum ativo cadastrado"]
        self.upd_combo_selecionar.configure(values=lista)
        self.upd_combo_selecionar.set(lista[0])

    def func_carregar_dados_atualizacao(self):
        item = self.upd_combo_selecionar.get()
        if item == "Nenhum ativo cadastrado" or not item:
            self.lbl_status.configure(
                text="⚠️ Selecione um ativo válido!", text_color="#facc15"
            )
            return
        try:
            id_val = int(item.split(" ")[1])
        except (IndexError, ValueError):
            return

        self.carregar_ativo_por_id(id_val)

    def carregar_ativo_por_id(self, id_val):
        if id_val in base_ativos:
            ativo = base_ativos[id_val]

            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, "end")
            self.upd_entry_id.insert(0, str(id_val))
            self.upd_entry_id.configure(state="disabled")

            self.upd_entry_hostname.delete(0, "end")
            self.upd_entry_hostname.insert(0, ativo.get("hostname", ""))

            self.upd_entry_responsavel.delete(0, "end")
            self.upd_entry_responsavel.insert(0, ativo.get("responsavel", ""))

            self.upd_entry_localizacao.delete(0, "end")
            self.upd_entry_localizacao.insert(0, ativo.get("localizacao", ""))

            self.upd_combo_tipo.set(
                ativo.get("tipo", TipoAtivo.SERVIDORES.value)
            )

            self.upd_lbl_titulo.configure(
                text=f"✏️ Editando Ativo ID: {id_val}",
                text_color=COR_TEXTO_DEST,
            )
            self.lbl_status.configure(
                text=f"📥 Dados do Ativo {id_val} carregados.",
                text_color=COR_TEXTO_DEST,
            )

    def func_executar_atualizacao(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(
                text="⚠️ Selecione um ativo para editar!", text_color="#facc15"
            )
            return

        valido, res_id = validar_id(id_str)
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(
                text="❌ O ativo informado não existe!", text_color="#ef4444"
            )
            return

        hostname_bruto = self.upd_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(
                text="🛡️ Erro: Hostname inválido!", text_color="#ef4444"
            )
            return

        vulnerabilidades_existentes = base_ativos[res_id].get(
            "vulnerabilidades", []
        )

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.upd_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.upd_entry_localizacao.get()),
            "tipo": self.upd_combo_tipo.get(),
            "vulnerabilidades": vulnerabilidades_existentes,
        }

        salvar_dados_ativos()
        self.lbl_status.configure(
            text=f"✅ Ativo {res_id} atualizado com sucesso!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    def func_deletar_ativo_selecionado(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(
                text="⚠️ Nenhum ativo selecionado para exclusão!",
                text_color="#facc15",
            )
            return

        valido, res_id = validar_id(id_str)
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(
                text="❌ Ativo não encontrado!", text_color="#ef4444"
            )
            return

        resposta = messagebox.askyesno(
            "Confirmar Exclusão",
            f"Tem certeza que deseja remover o ativo ID {res_id}?",
        )
        if resposta:
            del base_ativos[res_id]
            salvar_dados_ativos()

            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, "end")
            self.upd_entry_id.configure(state="disabled")
            self.upd_entry_hostname.delete(0, "end")
            self.upd_entry_responsavel.delete(0, "end")
            self.upd_entry_localizacao.delete(0, "end")
            self.upd_lbl_titulo.configure(
                text="Selecione um ativo acima para carregar",
                text_color="#94a3b8",
            )

            self.lbl_status.configure(
                text=f"🗑️ Ativo {res_id} removido com sucesso!",
                text_color=COR_TEXTO_VERDE,
            )
            self.func_atualizar_relatorio()
            self.func_atualizar_menu_selecao()

    # ==========================================
    # ABA DE GESTÃO DE VULNERABILIDADES (CVE)
    # ==========================================
    def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(
            self.tab_cve,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_cve.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(
            frame_cve,
            text="⚠️ Vincular / Consultar Vulnerabilidade CVE",
            font=("Segoe UI", 16, "bold"),
            text_color="#facc15",
        ).pack(pady=(10, 4))

        self.cve_entry_id = ctk.CTkEntry(
            frame_cve,
            placeholder_text="ID do Ativo Alvo (ex: 101)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cve_entry_id.pack(pady=5)

        self.cve_entry_codigo = ctk.CTkEntry(
            frame_cve,
            placeholder_text="Código CVE (ex: CVE-2021-44228)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cve_entry_codigo.pack(pady=5)

        # Configura navegação por Enter nos campos de entrada da aba CVE
        self.cve_entry_id.bind("<Return>", lambda e: self.cve_entry_codigo.focus())
        self.cve_entry_codigo.bind("<Return>", lambda e: self.func_buscar_cve_api())

        frame_btns_cve = ctk.CTkFrame(frame_cve, fg_color="transparent")
        frame_btns_cve.pack(pady=10)

        ctk.CTkButton(
            frame_btns_cve,
            text="Buscar / Processar CVE 🔍",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=180,
            command=self.func_buscar_cve_api,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            frame_btns_cve,
            text="Vincular ao Ativo 🔗",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            width=150,
            command=self.func_vincular_cve,
        ).pack(side="left", padx=5)

        # Caixa de texto com quebra automática de linha por palavras
        self.txt_cve_info = ctk.CTkTextbox(
            frame_cve,
            width=550,
            height=160,
            fg_color="#05070a",
            border_color=COR_BORDA,
            border_width=1,
            wrap="word",
        )
        self.txt_cve_info.pack(pady=10)
        self.txt_cve_info.insert(
            "1.0", "O resultado da consulta aparecerá aqui..."
        )

    def func_buscar_cve_api(self):
        cve_code = self.cve_entry_codigo.get().strip().upper()

        if not cve_code:
            messagebox.showwarning(
                "Aviso", "Por favor, digite um código de CVE!"
            )
            return

        self.lbl_status.configure(
            text="⏳ A processar validação, cache e API NVD...",
            text_color=COR_TEXTO_DEST,
        )
        self.update_idletasks()

        dados = consultar_cve_nvd(cve_code)
        self.txt_cve_info.delete("1.0", "end")

        if "erro" not in dados:
            rotulo, cor_hex, dica_acao = traduzir_severidade(dados["cvss"])
            origem_str = (
                "⚡ [CACHE LOCAL]"
                if dados.get("origem") == "local"
                else "🌐 [API NVD (Em Tempo Real)]"
            )

            res_texto = (
                f"📌 ID CVE: {dados['id']} ({origem_str})\n"
                f"📊 Pontuação CVSS: {dados['cvss']} / 10.0\n"
                f"🚨 Nível de Risco: {rotulo}\n"
                f"{dica_acao}\n\n"
                f"📝 Descrição (Português):\n{dados['descricao']}"
            )

            self.txt_cve_info.insert("1.0", res_texto)
            self.lbl_status.configure(
                text=f"✅ {dados['id']} processada! Severidade: {rotulo}",
                text_color=cor_hex,
            )
        else:
            self.txt_cve_info.insert("1.0", f"❌ Erro: {dados['erro']}")
            self.lbl_status.configure(
                text="❌ Erro na consulta.", text_color="#ef4444"
            )

    def func_vincular_cve(self):
        # 1. Validar ID do Ativo
        valido, res_id = validar_id(self.cve_entry_id.get().strip())
        if not valido or res_id not in base_ativos:
            messagebox.showerror(
                "Erro de Ativo", "ID de ativo inválido ou não encontrado na base!"
            )
            return

        cve_code = self.cve_entry_codigo.get().strip().upper()

        # 2. Validar se o formato da string é um formato CVE válido (ex: CVE-2021-44228)
        if not validar_cve(cve_code):
            messagebox.showerror(
                "Formato Inválido",
                "Código CVE com formato inválido!\nUse o padrão: CVE-AAAA-NNNNN (ex: CVE-2021-44228)"
            )
            return

        # 3. Consultar a API/Cache para verificar se a CVE realmente existe
        dados = consultar_cve_nvd(cve_code)
        if "erro" in dados:
            messagebox.showerror(
                "CVE Não Encontrada",
                f"A CVE '{cve_code}' não pôde ser vinculada:\n{dados['erro']}"
            )
            return

        # 4. Verificar se a CVE já está vinculada a este ativo específico
        if cve_code in base_ativos[res_id]["vulnerabilidades"]:
            messagebox.showwarning(
                "Duplicidade", f"A {cve_code} já está vinculada ao ativo ID {res_id}."
            )
            return

        # 5. Vinculação confirmada para CVE válida
        base_ativos[res_id]["vulnerabilidades"].append(cve_code)
        salvar_dados_ativos()

        self.lbl_status.configure(
            text=f"✅ {cve_code} vinculada com sucesso ao Ativo ID {res_id}!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()
   # ==========================================
    # 🚀 ABA DE RELATÓRIO E BUSCA (COMPLETA)
    # ==========================================
    def setup_aba_relatorio(self):
        frame_busca = ctk.CTkFrame(
            self.tab_relatorio,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_busca.pack(pady=10, padx=15, fill="x")

        # Campo de entrada para o filtro
        self.entry_busca = ctk.CTkEntry(
            frame_busca,
            placeholder_text=(
                "Filtrar por Hostname, Responsável, Tipo ou CVE..."
            ),
            width=380,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.entry_busca.pack(side="left", padx=10, pady=10)
        
        # Eventos e atalhos na barra de busca ⌨️
        self.entry_busca.bind(
            "<KeyRelease>", lambda e: self.func_atualizar_relatorio()
        )
        self.entry_busca.bind("<Escape>", lambda e: self.func_limpar_busca())
        self.entry_busca.bind("<Return>", lambda e: self.focus())

        # Botão Limpar Filtro
        ctk.CTkButton(
            frame_busca,
            text="Limpar Filtro 🧹",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=120,
            command=self.func_limpar_busca,
        ).pack(side="left", padx=5)

        # Botão Ver Detalhes 🔍
        ctk.CTkButton(
            frame_busca,
            text="Ver Detalhes 🔍",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            width=130,
            command=self.func_exibir_detalhes_ativo,
        ).pack(side="left", padx=5)

        # Estilo da Tabela Treeview
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=COR_CARD,
            foreground="#ffffff",
            rowheight=25,
            fieldbackground=COR_CARD,
            bordercolor=COR_BORDA,
        )
        style.map("Treeview", background=[("selected", COR_AZUL_PRINCIPAL)])
        style.configure(
            "Treeview.Heading",
            background="#090d14",
            foreground=COR_TEXTO_DEST,
            font=("Segoe UI", 10, "bold"),
        )

        self.tree_frame = ctk.CTkFrame(
            self.tab_relatorio, fg_color="transparent"
        )
        self.tree_frame.pack(fill="both", expand=True, padx=15, pady=5)

        cols = (
            "ID",
            "Hostname",
            "Tipo",
            "Responsável",
            "Localização",
            "Vulnerabilidades",
        )
        self.tree = ttk.Treeview(
            self.tree_frame, columns=cols, show="headings", height=12
        )

        # Larguras personalizadas das colunas
        larguras = {
            "ID": 70,
            "Hostname": 150,
            "Tipo": 140,
            "Responsável": 160,
            "Localização": 180,
            "Vulnerabilidades": 280,
        }

        for col in cols:
            self.tree.heading(
                col,
                text=col,
                command=lambda _col=col: self.func_ordenar_coluna(_col, False),
            )
            self.tree.column(
                col, anchor="center", width=larguras.get(col, 120), minwidth=80
            )

        # Ações do rato na tabela 🖱️
        self.tree.bind("<Double-1>", self.func_ao_dar_duplo_clique)
        self.tree.bind("<Button-3>", lambda e: self.func_exibir_detalhes_ativo())

        # Barras de rolagem (Vertical e Horizontal)
        scroll_y = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.tree.yview
        )
        scroll_x = ttk.Scrollbar(
            self.tree_frame, orient="horizontal", command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set
        )

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

    # ==========================================
    # ⚙️ MÉTODOS AUXILIARES DO RELATÓRIO
    # ==========================================
    def func_ordenar_coluna(self, col, reverse):
        lista_itens = [
            (self.tree.set(k, col), k) for k in self.tree.get_children("")
        ]

        try:
            lista_itens.sort(key=lambda x: int(x[0]), reverse=reverse)
        except ValueError:
            lista_itens.sort(key=lambda x: x[0].lower(), reverse=reverse)

        for index, (val, k) in enumerate(lista_itens):
            self.tree.move(k, "", index)

        self.tree.heading(
            col, command=lambda: self.func_ordenar_coluna(col, not reverse)
        )

    def func_ao_dar_duplo_clique(self, event):
        item_selecionado = self.tree.selection()
        if not item_selecionado:
            return

        valores_linha = self.tree.item(item_selecionado, "values")
        if valores_linha:
            id_ativo = int(valores_linha[0])
            self.carregar_ativo_por_id(id_ativo)
            self.tabview.set("✏️ Atualizar / Remover Ativo")

    def func_limpar_busca(self):
        self.entry_busca.delete(0, "end")
        self.func_atualizar_relatorio()

    def func_exibir_detalhes_ativo(self):
        item_selecionado = self.tree.selection()
        if not item_selecionado:
            messagebox.showwarning(
                "Aviso", "Por favor, selecione um ativo na tabela para ver os detalhes!"
            )
            return

        valores_linha = self.tree.item(item_selecionado, "values")
        id_ativo = int(valores_linha[0])
        ativo = base_ativos.get(id_ativo)

        if not ativo:
            messagebox.showerror("Erro", "Dados do ativo não encontrados!")
            return

        # Janela Modal / Popup de Detalhes
        janela_detalhes = ctk.CTkToplevel(self)
        janela_detalhes.title(f"🔍 Detalhes do Ativo - ID {id_ativo}")
        janela_detalhes.geometry("520x450")
        janela_detalhes.grab_set()

        frame_detalhes = ctk.CTkFrame(
            janela_detalhes,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_detalhes.pack(pady=15, padx=15, fill="both", expand=True)

        ctk.CTkLabel(
            frame_detalhes,
            text=f"💻 {ativo.get('hostname', 'N/A')}",
            font=("Segoe UI", 18, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(10, 5))

        info_texto = (
            f"🆔 ID: {id_ativo}\n"
            f"🏷️ Tipo: {ativo.get('tipo', 'N/A')}\n"
            f"👤 Responsável: {ativo.get('responsavel', 'N/A')}\n"
            f"📍 Localização: {ativo.get('localizacao', 'N/A')}\n"
        )

        ctk.CTkLabel(
            frame_detalhes,
            text=info_texto,
            font=("Segoe UI", 12),
            justify="left",
        ).pack(anchor="w", padx=20, pady=5)

        ctk.CTkLabel(
            frame_detalhes,
            text="⚠️ Vulnerabilidades Associadas:",
            font=("Segoe UI", 12, "bold"),
            text_color="#facc15",
        ).pack(anchor="w", padx=20, pady=(10, 2))

        txt_vuls = ctk.CTkTextbox(
            frame_detalhes,
            width=460,
            height=180,
            fg_color="#05070a",
            border_color=COR_BORDA,
            border_width=1,
            wrap="word",
        )
        txt_vuls.pack(padx=20, pady=5, fill="both", expand=True)

        vulnerabilidades = ativo.get("vulnerabilidades", [])
        if not vulnerabilidades:
            txt_vuls.insert("1.0", "Nenhuma vulnerabilidade vinculada a este ativo.")
        else:
            relatorio_vuls = ""
            for cve in vulnerabilidades:
                cve_info = cache_cve.get(cve, {})
                cvss = cve_info.get("cvss", "N/A")
                desc = cve_info.get("descricao", "Descrição não carregada no cache.")
                relatorio_vuls += f"• {cve} (CVSS: {cvss})\n  {desc}\n\n"

            txt_vuls.insert("1.0", relatorio_vuls.strip())

        ctk.CTkButton(
            frame_detalhes,
            text="Fechar ❌",
            fg_color="#ef4444",
            hover_color="#dc2626",
            width=100,
            command=janela_detalhes.destroy,
        ).pack(pady=10)

    def func_atualizar_relatorio(self):
        if not hasattr(self, "tree"):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        termo = self.entry_busca.get().strip().lower()

        for id_ativo, info in sorted(base_ativos.items()):
            vulnerabilidades = info.get("vulnerabilidades", [])
            lista_vuls = []

            for v in vulnerabilidades:
                if isinstance(v, dict):
                    val = (
                        v.get("id")
                        or v.get("cve")
                        or v.get("nome")
                        or str(v)
                    )
                    lista_vuls.append(str(val))
                else:
                    lista_vuls.append(str(v))

            vuls_str = ", ".join(lista_vuls) if lista_vuls else "Nenhuma"

            if termo:
                match_id = termo in str(id_ativo)
                match_host = termo in info.get("hostname", "").lower()
                match_resp = termo in info.get("responsavel", "").lower()
                match_tipo = termo in info.get("tipo", "").lower()
                match_cve = termo in vuls_str.lower()

                if not (
                    match_id
                    or match_host
                    or match_resp
                    or match_tipo
                    or match_cve
                ):
                    continue

            self.tree.insert(
                "",
                "end",
                values=(
                    id_ativo,
                    info.get("hostname", ""),
                    info.get("tipo", ""),
                    info.get("responsavel", ""),
                    info.get("localizacao", ""),
                    vuls_str,
                ),
            )
# ==========================================
# 🚀 PONTO DE ENTRADA DO APLICATIVO
# ==========================================
def iniciar_aplicacao():
    dados_sessao = {}

    def callback_login_sucesso(nome_usuario, role_usuario, usuario):
        
        dados_sessao["usuario"] = nome_usuario
        dados_sessao["role"] = role_usuario
        dados_sessao["id"] = usuario

        
        try:
            if login_app and login_app.winfo_exists():
                login_app.destroy()
        except Exception:
            pass

    
    login_app = JanelaLogin(callback_login_sucesso)
    login_app.mainloop()

    
    if dados_sessao:
        app = AplicacaoInventario(
            dados_sessao["usuario"], 
            dados_sessao["role"], 
            dados_sessao["id"]
        )
        app.mainloop()


if __name__ == "__main__":
    iniciar_aplicacao()