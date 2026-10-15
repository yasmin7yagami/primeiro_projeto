# ==========================================
# JANELA DE REGISTRO DE USUÁRIO (ADMIN) 👤
# ==========================================
class JanelaCadastroUsuario(ctk.CTkToplevel):

    def __init__(self, parent):
        super().__init__(parent)
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

        if hasattr(self.master, "func_atualizar_lista_usuarios_adm"):
            self.master.func_atualizar_lista_usuarios_adm()

        self.after(1200, self.destroy)
 # ==========================================
    # ABA EXCLUSIVA DE ADMIN
    # ==========================================
    def setup_aba_admin(self):
        frame_criar = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_criar.pack(pady=(10, 5), padx=15, fill="x")

        ctk.CTkLabel(
            frame_criar,
            text="👤 Cadastrar Novo Usuário",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_VERDE_NEON,
        ).pack(pady=(8, 4))
        ctk.CTkButton(
            frame_criar,
            text="Criar Usuário ➕",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            font=("Segoe UI", 12, "bold"),
            width=200,
            command=self.func_abrir_cadastro_admin,
        ).pack(pady=8)

        frame_adm = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_adm.pack(pady=5, padx=15, fill="x")

        ctk.CTkLabel(
            frame_adm,
            text="🔑 Alterar Permissão de Usuário",
            font=("Segoe UI", 15, "bold"),
            text_color=COR_TEXTO_DEST,
        ).pack(pady=(8, 4))

        self.combo_usuarios_adm = ctk.CTkOptionMenu(
            frame_adm,
            values=["Carregando..."],
            width=280,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.combo_usuarios_adm.pack(pady=4)

        self.combo_role_adm = ctk.CTkComboBox(
            frame_adm,
            values=["user", "admin"],
            width=280,
            fg_color="#101720",
            button_color=COR_AZUL_PRINCIPAL,
        )
        self.combo_role_adm.pack(pady=4)

        ctk.CTkButton(
            frame_adm,
            text="Atualizar Permissão 🔄",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=200,
            command=self.func_alterar_permissao,
        ).pack(pady=8)

        frame_del_usr = ctk.CTkFrame(
            self.tab_admin,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_del_usr.pack(pady=5, padx=15, fill="x")

        ctk.CTkLabel(
            frame_del_usr,
            text="🗑️ Remover Usuário Cadastrado",
            font=("Segoe UI", 15, "bold"),
            text_color="#f87171",
        ).pack(pady=(8, 4))

        self.combo_del_usuario = ctk.CTkOptionMenu(
            frame_del_usr,
            values=["Carregando..."],
            width=280,
            fg_color="#101720",
            button_color="#dc2626",
        )
        self.combo_del_usuario.pack(pady=4)

        ctk.CTkButton(
            frame_del_usr,
            text="Excluir Usuário ❌",
            fg_color="#dc2626",
            hover_color="#991b1b",
            width=200,
            command=self.func_remover_usuario,
        ).pack(pady=8)

        self.func_atualizar_lista_usuarios_adm()

    def func_abrir_cadastro_admin(self):
        JanelaCadastroUsuario(self)

    def func_atualizar_lista_usuarios_adm(self):
        usuarios = carregar_usuarios()
        lista = [f"{u} ({d.get('role', 'user')})" for u, d in usuarios.items()]

        self.combo_usuarios_adm.configure(values=lista)
        if lista:
            self.combo_usuarios_adm.set(lista[0])

        lista_puros = list(usuarios.keys())
        self.combo_del_usuario.configure(values=lista_puros)
        if lista_puros:
            self.combo_del_usuario.set(lista_puros[0])

    def func_alterar_permissao(self):
        item = self.combo_usuarios_adm.get()
        if not item or "(" not in item:
            return

        usuario_alvo = item.split(" ")[0]
        novo_role = self.combo_role_adm.get()

        if atualizar_role_usuario(usuario_alvo, novo_role):
            self.lbl_status.configure(
                text=f"✅ Permissão de '{usuario_alvo}' alterada para '{novo_role}'.",
                text_color=COR_TEXTO_VERDE,
            )
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.lbl_status.configure(
                text="❌ Falha ao alterar permissão.", text_color="#ef4444"
            )

    def func_remover_usuario(self):
        usuario_alvo = self.combo_del_usuario.get()
        if not usuario_alvo:
            return

        sucesso, msg = deletar_usuario(usuario_alvo)
        if sucesso:
            self.lbl_status.configure(
                text=f"✅ {msg}", text_color=COR_TEXTO_VERDE
            )
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.lbl_status.configure(text=f"❌ {msg}", text_color="#ef4444")
