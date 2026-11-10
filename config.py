import os

# ==========================================
# 📁 CAMINHOS DOS ARQUIVOS (DINÂMICOS)
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NOME_ARQUIVO_ATIVOS = os.path.join(BASE_DIR, "base_ativos.json")
NOME_ARQUIVO_USUARIOS = os.path.join(BASE_DIR, "usuarios.json")
NOME_ARQUIVO_CVES = os.path.join(BASE_DIR, "cves_salvas.json")

# ==========================================
# 🎨 PALETA DE CORES
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
# 📏 CONFIGURAÇÃO DE TEMA E ESCALAMENTO (UI)
# ==========================================
def inicializar_tema():
    """Configura o tema do CustomTkinter apenas quando executado em modo com interface gráfica."""
    try:
        import customtkinter as ctk

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        ctk.set_widget_scaling(1.0)
        ctk.set_window_scaling(1.0)
    except ImportError:
        pass
