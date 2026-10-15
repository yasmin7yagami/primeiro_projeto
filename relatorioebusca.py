# ==========================================
#  ABA DE RELATÓRIO E BUSCA
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
        self.entry_busca.bind(
            "<KeyRelease>", lambda e: self.func_atualizar_relatorio()
        )

        ctk.CTkButton(
            frame_busca,
            text="Limpar Filtro 🧹",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=120,
            command=self.func_limpar_busca,
        ).pack(side="left", padx=5)

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

        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=120)

        self.tree.column("ID", width=60)
        self.tree.column("Vulnerabilidades", width=180)

        scrollbar = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

def func_limpar_busca(self):
        self.entry_busca.delete(0, "end")
        self.func_atualizar_relatorio()

def func_atualizar_relatorio(self):
        if not hasattr(self, "tree"):
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        termo = self.entry_busca.get().strip().lower()

        for id_ativo, info in sorted(base_ativos.items()):
            vuls_list = info.get("vulnerabilidades", [])
            if vuls_list:
                # Extracts a specific key (like 'cve' or 'nome') if it's a dict, 
                # otherwise converts the dictionary safely to a string
                vuls_str = ", ".join(
                    [
                        str(v.get("cve", v.get("nome", v))) if isinstance(v, dict) else str(v)
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

