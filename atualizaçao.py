# ==========================================
    # 2. ATUALIZAÇÃO E REMOÇÃO DE ATIVO
    # ==========================================
def setup_aba_atualizar(self):
        frame_select = ctk.CTkFrame(
            self.tab_atualizar,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_select.pack(pady=10, padx=15, fill="x")

        ctk.CTkLabel(
            frame_select,
            text="🔍 Selecionar Ativo Existente",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(8, 4))

        sub_select = ctk.CTkFrame(frame_select, fg_color="transparent")
        sub_select.pack(pady=(0, 8))

        self.upd_combo_selecionar = ctk.CTkOptionMenu(
            sub_select,
            values=["Nenhum ativo cadastrado"],
            width=250,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.upd_combo_selecionar.pack(side="left", padx=5)

        self.btn_carregar_ativo = ctk.CTkButton(
            sub_select,
            text="Carregar Dados 📥",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=140,
            command=self.func_carregar_dados_atualizacao,
        )
        self.btn_carregar_ativo.pack(side="left", padx=5)

        frame_upd = ctk.CTkFrame(
            self.tab_atualizar,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_upd.pack(pady=5, padx=15, fill="x")

        self.upd_lbl_titulo = ctk.CTkLabel(
            frame_upd,
            text="Selecione um ativo acima para carregar",
            font=("Segoe UI", 13, "bold"),
            text_color="#94a3b8",
        )
        self.upd_lbl_titulo.pack(pady=6)

        self.upd_entry_id = ctk.CTkEntry(
            frame_upd,
            placeholder_text="ID",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
            state="disabled",
        )
        self.upd_entry_id.pack(pady=4)

        self.upd_entry_hostname = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Hostname",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_hostname.pack(pady=4)

        self.upd_entry_responsavel = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Responsável",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_responsavel.pack(pady=4)

        self.upd_entry_localizacao = ctk.CTkEntry(
            frame_upd,
            placeholder_text="Localização",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.upd_entry_localizacao.pack(pady=4)

        self.upd_combo_tipo = ctk.CTkComboBox(
            frame_upd,
            values=[t.value for t in TipoAtivo],
            width=320,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.upd_combo_tipo.pack(pady=4)

        frame_acoes = ctk.CTkFrame(frame_upd, fg_color="transparent")
        frame_acoes.pack(pady=10)

        self.btn_salvar_atualizacao = ctk.CTkButton(
            frame_acoes,
            text="Salvar Alterações 🔄",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            font=("Segoe UI", 12, "bold"),
            width=170,
            command=self.func_executar_atualizacao,
        )
        self.btn_salvar_atualizacao.pack(side="left", padx=5)

        self.btn_deletar = ctk.CTkButton(
            frame_acoes,
            text="Remover Ativo 🗑️",
            fg_color="#dc2626",
            hover_color="#991b1b",
            font=("Segoe UI", 12, "bold"),
            width=150,
            command=self.func_deletar_ativo_selecionado,
        )
        self.btn_deletar.pack(side="left", padx=5)

def func_atualizar_menu_selecao(self):
        if not hasattr(self, "upd_combo_selecionar"):
            return
        lista = [
            f"ID: {k} - {v.get('hostname', '')}" for k, v in base_ativos.items()
        ]
        if not lista:
            lista = ["Nenhum ativo cadastrado"]
        self.upd_combo_selecionar.configure(values=lista)
        self.upd_combo_selecionar.set(lista[0])

def func_carregar_dados_atualizacao(self):
        item = self.upd_combo_selecionar.get()
        if item == "Nenhum ativo cadastrado" or not item:
            self.lbl_status.configure(
                text="⚠️ Selecione um ativo válido!", text_color="#facc15"
            )
            return
        try:
            id_val = int(item.split(" ")[1])
        except (IndexError, ValueError):
            return

        self.carregar_ativo_por_id(id_val)

def carregar_ativo_por_id(self, id_val):
        if id_val in base_ativos:
            ativo = base_ativos[id_val]

            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, "end")
            self.upd_entry_id.insert(0, str(id_val))
            self.upd_entry_id.configure(state="disabled")

            self.upd_entry_hostname.delete(0, "end")
            self.upd_entry_hostname.insert(0, ativo.get("hostname", ""))

            self.upd_entry_responsavel.delete(0, "end")
            self.upd_entry_responsavel.insert(0, ativo.get("responsavel", ""))

            self.upd_entry_localizacao.delete(0, "end")
            self.upd_entry_localizacao.insert(0, ativo.get("localizacao", ""))

            self.upd_combo_tipo.set(
                ativo.get("tipo", TipoAtivo.SERVIDORES.value)
            )

            self.upd_lbl_titulo.configure(
                text=f"✏️ Editando Ativo ID: {id_val}",
                text_color=COR_TEXTO_DEST,
            )
            self.lbl_status.configure(
                text=f"📥 Dados do Ativo {id_val} carregados.",
                text_color=COR_TEXTO_DEST,
            )

def func_executar_atualizacao(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(
                text="⚠️ Selecione um ativo para editar!", text_color="#facc15"
            )
            return

        valido, res_id = validar_id(id_str)
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(
                text="❌ O ativo informado não existe!", text_color="#ef4444"
            )
            return

        hostname_bruto = self.upd_entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(
                text="🛡️ Erro: Hostname inválido!", text_color="#ef4444"
            )
            return

        vulnerabilidades_existentes = base_ativos[res_id].get(
            "vulnerabilidades", []
        )

        base_ativos[res_id] = {
            "hostname": sanitizar_texto(hostname_bruto),
            "responsavel": sanitizar_texto(self.upd_entry_responsavel.get()),
            "localizacao": sanitizar_texto(self.upd_entry_localizacao.get()),
            "tipo": self.upd_combo_tipo.get(),
            "vulnerabilidades": vulnerabilidades_existentes,
        }

        salvar_dados_ativos()
        self.lbl_status.configure(
            text=f"✅ Ativo {res_id} atualizado com sucesso!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

def func_deletar_ativo_selecionado(self):
        id_str = self.upd_entry_id.get().strip()
        if not id_str:
            self.lbl_status.configure(
                text="⚠️ Nenhum ativo selecionado para exclusão!",
                text_color="#facc15",
            )
            return

        valido, res_id = validar_id(id_str)
        if not valido or res_id not in base_ativos:
            self.lbl_status.configure(
                text="❌ Ativo não encontrado!", text_color="#ef4444"
            )
            return

        resposta = messagebox.askyesno(
            "Confirmar Exclusão",
            f"Tem certeza que deseja remover o ativo ID {res_id}?",
        )
        if resposta:
            del base_ativos[res_id]
            salvar_dados_ativos()

            self.upd_entry_id.configure(state="normal")
            self.upd_entry_id.delete(0, "end")
            self.upd_entry_id.configure(state="disabled")
            self.upd_entry_hostname.delete(0, "end")
            self.upd_entry_responsavel.delete(0, "end")
            self.upd_entry_localizacao.delete(0, "end")
            self.upd_lbl_titulo.configure(
                text="Selecione um ativo acima para carregar",
                text_color="#94a3b8",
            )

            self.lbl_status.configure(
                text=f"🗑️ Ativo {res_id} removido com sucesso!",
                text_color=COR_TEXTO_VERDE,
            )
            self.func_atualizar_relatorio()
            self.func_atualizar_menu_selecao()