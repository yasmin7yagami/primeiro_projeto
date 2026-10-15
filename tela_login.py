# ==========================================
# TELA DE LOGIN 🔐
# ==========================================
class JanelaLogin(ctk.CTk):

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
        self.entry_senha.bind(
            "<Return>", lambda event: self.func_efetuar_login()
        )

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
        usuarios = carregar_usuarios()

        if usuario in usuarios and verificar_senha(
            senha, usuarios[usuario]["hash"]
        ):
            dados_user = usuarios[usuario]
            nome_usuario = dados_user.get("nome", usuario)
            role_usuario = dados_user.get("role", "user")

            self.destroy()
            self.callback_sucesso(nome_usuario, role_usuario, usuario)
        else:
            self.lbl_msg.configure(
                text="❌ Usuário ou senha incorretos!", text_color="#ef4444"
            )

# ==========================================
# ALTERAÇÃO DE PALAVRA-PASSE 🔑
# ==========================================
    def abrir_janela_alterar_senha(self):
        self.janela_senha = ctk.CTkToplevel(self)
        self.janela_senha.title("Alterar Palavra-Passe")
        self.janela_senha.geometry("380x320")
        self.janela_senha.configure(fg_color=COR_FUNDO)
        self.janela_senha.grab_set()

        card = ctk.CTkFrame(
            self.janela_senha,
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

        usuarios = carregar_usuarios()
        if self.login_id not in usuarios:
            messagebox.showerror("Erro ⚠️", "Usuário não encontrado!")
            return

        if not verificar_senha(atual, usuarios[self.login_id]["hash"]):
            messagebox.showerror("Erro ⚠️", "Senha atual incorreta!")
            return

        if nova != confirma:
            messagebox.showerror(
                "Erro ⚠️", "A nova senha e a confirmação não coincidem!"
            )
            return

        if len(nova) < 6:
            messagebox.showwarning(
                "Aviso 🛡️", "A nova senha deve ter pelo menos 6 caracteres."
            )
            return

        usuarios[self.login_id]["hash"] = gerar_hash_senha(nova)
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)

        messagebox.showinfo("Sucesso ✅", "Senha alterada com sucesso!")
        self.janela_senha.destroy()