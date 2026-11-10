import customtkinter as ctk
from config import (
    COR_AZUL_HOVER,
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_CARD,
    COR_FUNDO,
    COR_TEXTO_DEST,
)
from services.auth_service import autenticar_usuario


class JanelaLogin(ctk.CTk):
    """Janela de autenticação inicial para acesso ao sistema."""

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
        self.entry_senha.bind("<Return>", lambda event: self.func_efetuar_login())

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

        sucesso, resultado = autenticar_usuario(usuario, senha)
        if sucesso:
            nome = resultado["nome"]
            role = resultado["role"]
            login_id = resultado["login_id"]
            self.destroy()
            self.callback_sucesso(nome, role, login_id)
        else:
            self.lbl_msg.configure(text=f"❌ {resultado}", text_color="#ef4444")
