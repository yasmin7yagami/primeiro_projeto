# ==========================================
    #  CADASTRO DE NOVO ATIVO
    # ==========================================
def setup_aba_cadastrar(self):
        frame_cad = ctk.CTkFrame(
            self.tab_cadastrar,
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
        valido, res_id = validar_id(self.cad_entry_id.get().strip())
        if not valido:
            self.lbl_status.configure(
                text=f"🛡️ Erro de Validação: {res_id}", text_color="#ef4444"
            )
            return

        if res_id in base_ativos:
            self.lbl_status.configure(
                text=f"❌ Erro: O ID {res_id} já existe!", text_color="#ef4444"
            )
            return

        hostname_bruto = self.cad_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(
                text="🛡️ Erro: Hostname inválido!", text_color="#ef4444"
            )
            return

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.cad_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.cad_entry_localizacao.get()),
            "tipo": self.cad_combo_tipo.get(),
            "vulnerabilidades": [],
        }

        salvar_dados_ativos()
        self.lbl_status.configure(
            text=f"✅ Novo Ativo {res_id} registrado com sucesso!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

        self.cad_entry_id.delete(0, "end")
        self.cad_entry_hostname.delete(0, "end")
        self.cad_entry_responsavel.delete(0, "end")
        self.cad_entry_localizacao.delete(0, "end")
