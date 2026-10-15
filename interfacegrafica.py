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
        return texto_ingles  # Se falhar a tradução, devolve em inglês

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
            text=f"👤 {self.usuario_logado} {self.role_logado.upper()})",
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
# 🚀 PONTO DE ENTRADA DO APLICATIVO
# ==========================================
def iniciar_aplicacao():

    def callback_login_sucesso(nome_usuario, role_usuario, login_id):
        app = AplicacaoInventario(nome_usuario, role_usuario, login_id)
        app.mainloop()

    login_app = JanelaLogin(callback_login_sucesso)
    login_app.mainloop()


if __name__ == "__main__":
    iniciar_aplicacao()
