from tkinter import ttk
import customtkinter as ctk
from config import (
    COR_AZUL_HOVER,
    COR_AZUL_PRINCIPAL,
    COR_BORDA,
    COR_CARD,
    COR_TEXTO_DEST,
    COR_TEXTO_VERDE,
)
from services.asset_service import obter_base_ativos
from services.risco_service import calcular_risco_linear


class TabRelatorio(ctk.CTkFrame):
    """Aba de relatórios, listagem tabular, busca de ativos e consulta do Modelo Linear de Risco (Requisito 4)."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        # Frame superior com busca e ações
        frame_busca = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_busca.pack(pady=10, padx=15, fill="x")

        self.entry_busca = ctk.CTkEntry(
            frame_busca,
            placeholder_text="Filtrar por Hostname, Responsável, Tipo ou CVE...",
            width=360,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.entry_busca.pack(side="left", padx=10, pady=10)
        self.entry_busca.bind("<KeyRelease>", lambda e: self.func_atualizar_relatorio())

        ctk.CTkButton(
            frame_busca,
            text="Limpar Filtro 🧹",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=110,
            command=self.func_limpar_busca,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            frame_busca,
            text="Recalcular Risco ⚡",
            fg_color="#059669",
            hover_color="#047857",
            width=140,
            command=self.func_atualizar_relatorio,
        ).pack(side="right", padx=10)

        # Configuração visual da tabela (Treeview)
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

        self.tree_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.tree_frame.pack(fill="both", expand=True, padx=15, pady=5)

        # Colunas com Risco Próprio e Risco Efetivo (Requisito 4 da Tabela 1)
        cols = (
            "ID",
            "Hostname",
            "Tipo",
            "Responsável",
            "Localização",
            "Vulnerabilidades",
            "Risco Próprio (b)",
            "Risco Efetivo (x)",
        )
        self.tree = ttk.Treeview(self.tree_frame, columns=cols, show="headings", height=12)

        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=110)

        self.tree.column("ID", width=50)
        self.tree.column("Vulnerabilidades", width=140)
        self.tree.column("Risco Próprio (b)", width=120)
        self.tree.column("Risco Efetivo (x)", width=120)

        scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Barra de status do Modelo de Álgebra Linear (Requisito 4)
        self.frame_status_risco = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        self.frame_status_risco.pack(pady=8, padx=15, fill="x")

        self.lbl_status_risco = ctk.CTkLabel(
            self.frame_status_risco,
            text="📊 Modelo Linear (I - A)x = b: Inicializando...",
            font=("Segoe UI", 11, "bold"),
            text_color=COR_TEXTO_VERDE,
        )
        self.lbl_status_risco.pack(side="left", padx=12, pady=6)

    def func_limpar_busca(self):
        self.entry_busca.delete(0, "end")
        self.func_atualizar_relatorio()

    def func_atualizar_relatorio(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        termo = self.entry_busca.get().strip().lower()
        ativos = obter_base_ativos()

        # Executa a Análise de Risco por Álgebra Linear (Requisito 4)
        res_risco = calcular_risco_linear()
        mapa_risco = {}
        if res_risco.sucesso:
            for item in res_risco.tabela_detalhada:
                mapa_risco[item["id"]] = (item["risco_proprio"], item["risco_efetivo"])

            status_inv = "Invertível ✅" if res_risco.invertivel else "Não Invertível ❌"
            self.lbl_status_risco.configure(
                text=(
                    f"📊 Modelo Linear: (I - A)x = b | Matriz (I - A): {status_inv} | "
                    f"det(I - A) = {res_risco.determinante:.4f} | Ativos: {len(ativos)}"
                ),
                text_color=COR_TEXTO_VERDE if res_risco.invertivel else "#ef4444",
            )
        else:
            self.lbl_status_risco.configure(
                text=f"⚠️ {res_risco.mensagem}",
                text_color="#fbbf24",
            )

        for id_ativo, info in sorted(ativos.items()):
            vuls_list = info.get("vulnerabilidades", [])
            if vuls_list:
                vuls_str = ", ".join(
                    [
                        str(v.get("cve", v.get("nome", v)))
                        if isinstance(v, dict)
                        else str(v)
                        for v in vuls_list
                    ]
                )
            else:
                vuls_str = "Nenhuma"

            if termo:
                match_id = termo in str(id_ativo)
                match_host = termo in info.get("hostname", "").lower()
                match_resp = termo in info.get("responsavel", "").lower()
                match_tipo = termo in info.get("tipo", "").lower()
                match_cve = termo in vuls_str.lower()

                if not (match_id or match_host or match_resp or match_tipo or match_cve):
                    continue

            # Obtém os riscos calculados pela Álgebra Linear
            r_proprio, r_efetivo = mapa_risco.get(id_ativo, (0.0, 0.0))

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
                    f"{r_proprio:.2f}",
                    f"{r_efetivo:.2f}",
                ),
            )
