import customtkinter as ctk
from config import (
    COR_AZUL_HOVER,
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_CARD,
    COR_FUNDO,
    COR_TEXTO_DEST,
    COR_TEXTO_VERDE,
)
from services.asset_service import carregar_dados_ativos
from ui.password_modal import JanelaAlterarSenha
from ui.tabs import (
    TabAdmin,
    TabAtualizar,
    TabCadastrar,
    TabCVE,
    TabRelatorio,
)


class AplicacaoInventario(ctk.CTk):
    """Janela principal da aplicação com abas e cabeçalho de navegação."""

    def __init__(self, usuario_logado, role_logado, login_id, on_logout=None):
        super().__init__()
        self.usuario_logado = usuario_logado
        self.role_logado = role_logado
        self.login_id = login_id
        self.on_logout = on_logout

        self.title("UFU - CIBERSEGURANÇA 🔒")
        self.geometry("900x780")
        self.configure(fg_color=COR_FUNDO)
        self.resizable(True, True)

        # Carrega dados do disco para memória
        carregar_dados_ativos()

        self.scroll_container = ctk.CTkScrollableFrame(
            self, fg_color=COR_FUNDO, bg_color=COR_FUNDO
        )
        self.scroll_container.pack(fill="both", expand=True, padx=5, pady=5)

        # Cabeçalho
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

        # Gerenciador de Abas (Tabview)
        self.tabview = ctk.CTkTabview(
            self.scroll_container,
            corner_radius=10,
            fg_color=COR_CARD,
            segmented_button_fg_color="#090d14",
            segmented_button_selected_color=COR_AZUL_PRINCIPAL,
            segmented_button_selected_hover_color=COR_AZUL_HOVER,
        )
        self.tabview.pack(pady=5, padx=10, fill="both", expand=True)

        # Configuração das páginas de abas
        tab_cad = self.tabview.add("➕ Novo Ativo")
        self.tab_cadastrar_view = TabCadastrar(tab_cad, self)
        self.tab_cadastrar_view.pack(fill="both", expand=True)

        tab_upd = self.tabview.add("✏️ Atualizar / Remover Ativo")
        self.tab_atualizar_view = TabAtualizar(tab_upd, self)
        self.tab_atualizar_view.pack(fill="both", expand=True)

        tab_cve = self.tabview.add("⚠️ Vulnerabilidades")
        self.tab_cve_view = TabCVE(tab_cve, self)
        self.tab_cve_view.pack(fill="both", expand=True)

        tab_rel = self.tabview.add("📊 Relatório & Busca")
        self.tab_relatorio_view = TabRelatorio(tab_rel, self)
        self.tab_relatorio_view.pack(fill="both", expand=True)

        if self.role_logado == "admin":
            tab_adm = self.tabview.add("🔐 Gestão Usuários")
            self.tab_admin_view = TabAdmin(tab_adm, self)
            self.tab_admin_view.pack(fill="both", expand=True)

        # Barra de status no rodapé
        self.lbl_status = ctk.CTkLabel(
            self.scroll_container,
            text=f"🔒 Sessão iniciada como '{self.usuario_logado}'.",
            font=("Segoe UI", 12, "bold"),
            text_color="#94a3b8",
        )
        self.lbl_status.pack(pady=8)

        # Atualização inicial dos dados
        self.atualizar_telas()

    def set_status(self, texto, cor=None):
        """Atualiza a mensagem na barra de status inferior."""
        self.lbl_status.configure(text=texto, text_color=cor if cor else "#94a3b8")

    def atualizar_telas(self):
        """Sincroniza os dados entre todas as abas."""
        if hasattr(self, "tab_relatorio_view"):
            self.tab_relatorio_view.func_atualizar_relatorio()
        if hasattr(self, "tab_atualizar_view"):
            self.tab_atualizar_view.atualizar_selecao()

    def carregar_ativo_por_id(self, id_val):
        """Carrega os dados de um ativo diretamente na aba de atualização."""
        if hasattr(self, "tab_atualizar_view"):
            self.tab_atualizar_view.carregar_ativo_por_id(id_val)
            self.tabview.set("✏️ Atualizar / Remover Ativo")

    def abrir_janela_alterar_senha(self):
        """Abre o modal de alteração de senha."""
        JanelaAlterarSenha(self, self.login_id)

    def func_efetuar_logout(self):
        """Encerra a sessão e retorna à tela de login."""
        self.destroy()
        if callable(self.on_logout):
            self.on_logout()
