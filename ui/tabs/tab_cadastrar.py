import customtkinter as ctk
from config import (
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_TEXTO_VERDE,
    COR_VERDE_HOVER,
    COR_VERDE_NEON,
)
from models import TipoAtivo
from services.asset_service import cadastrar_ativo


class TabCadastrar(ctk.CTkFrame):
    """Aba de cadastro de novos ativos no inventário."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        frame_cad = ctk.CTkFrame(
            self,
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
        id_str = self.cad_entry_id.get().strip()
        hostname = self.cad_entry_hostname.get()
        responsavel = self.cad_entry_responsavel.get()
        localizacao = self.cad_entry_localizacao.get()
        tipo = self.cad_combo_tipo.get()

        sucesso, msg = cadastrar_ativo(
            id_str, hostname, responsavel, localizacao, tipo
        )

        if sucesso:
            self.app.set_status(f"✅ {msg}", COR_TEXTO_VERDE)
            self.app.atualizar_telas()

            self.cad_entry_id.delete(0, "end")
            self.cad_entry_hostname.delete(0, "end")
            self.cad_entry_responsavel.delete(0, "end")
            self.cad_entry_localizacao.delete(0, "end")
        else:
            self.app.set_status(f"🛡️ {msg}", "#ef4444")
