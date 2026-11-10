import customtkinter as ctk
from config import (
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_CARD,
    COR_FUNDO,
    COR_TEXTO_VERDE,
    COR_VERDE_HOVER,
    COR_VERDE_NEON,
)
from services.auth_service import salvar_usuario
from utils import sanitizar_texto


class JanelaCadastroUsuario(ctk.CTkToplevel):
    """Modal para cadastro de novos usuários pelo Administrador."""

    def __init__(self, parent, on_user_created=None):
        super().__init__(parent)
        self.on_user_created = on_user_created

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

        if callable(self.on_user_created):
            self.on_user_created()
        elif hasattr(self.master, "func_atualizar_lista_usuarios_adm"):
            self.master.func_atualizar_lista_usuarios_adm()

        self.after(1200, self.destroy)
