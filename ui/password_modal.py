from tkinter import messagebox
import customtkinter as ctk
from config import (
    COR_BORDA,
    COR_CARD,
    COR_FUNDO,
    COR_TEXTO_DEST,
    COR_VERDE_HOVER,
    COR_VERDE_NEON,
)
from services.auth_service import alterar_senha_usuario


class JanelaAlterarSenha(ctk.CTkToplevel):
    """Modal para alteração de senha do usuário logado."""

    def __init__(self, parent, login_id):
        super().__init__(parent)
        self.login_id = login_id

        self.title("Alterar Palavra-Passe")
        self.geometry("380x320")
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

        if nova != confirma:
            messagebox.showerror(
                "Erro ⚠️", "A nova senha e a confirmação não coincidem!"
            )
            return

        sucesso, msg = alterar_senha_usuario(self.login_id, atual, nova)
        if sucesso:
            messagebox.showinfo("Sucesso ✅", msg)
            self.destroy()
        else:
            messagebox.showerror("Erro ⚠️", msg)
