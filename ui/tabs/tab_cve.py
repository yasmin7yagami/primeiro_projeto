from tkinter import messagebox
import customtkinter as ctk
from config import (
    COR_AZUL_HOVER,
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_TEXTO_DEST,
    COR_TEXTO_VERDE,
    COR_VERDE_HOVER,
    COR_VERDE_NEON,
)
from services.asset_service import vincular_cve_ao_ativo
from services.cve_service import consultar_cve_nvd, traduzir_severidade
from utils import validar_cve


class TabCVE(ctk.CTkFrame):
    """Aba para consulta de vulnerabilidades na API NVD e vinculação aos ativos."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        frame_cve = ctk.CTkFrame(
            self,
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

        self.txt_cve_info = ctk.CTkTextbox(
            frame_cve,
            width=550,
            height=160,
            fg_color="#05070a",
            border_color=COR_BORDA,
            border_width=1,
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

        self.app.set_status(
            "⏳ A processar validação, cache e API NVD...", COR_TEXTO_DEST
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
            self.app.set_status(
                f"✅ {dados['id']} processada! Severidade: {rotulo}", cor_hex
            )
        else:
            self.txt_cve_info.insert("1.0", f"❌ Erro: {dados['erro']}")
            self.app.set_status("❌ Erro na consulta.", "#ef4444")

    def func_vincular_cve(self):
        id_str = self.cve_entry_id.get().strip()
        cve_code = self.cve_entry_codigo.get().strip().upper()

        if not validar_cve(cve_code):
            messagebox.showerror(
                "Erro",
                "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)",
            )
            return

        sucesso, msg = vincular_cve_ao_ativo(id_str, cve_code)
        if sucesso:
            self.app.set_status(f"✅ {msg}", COR_TEXTO_VERDE)
            self.app.atualizar_telas()
        else:
            messagebox.showwarning("Aviso", msg)
