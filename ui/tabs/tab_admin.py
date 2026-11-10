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
from services.auth_service import (
    atualizar_role_usuario,
    carregar_usuarios,
    deletar_usuario,
)
from ui.user_modal import JanelaCadastroUsuario


class TabAdmin(ctk.CTkFrame):
    """Aba exclusiva de administradores para gestão de operadores e permissões."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app

        # 1. Criação de Usuário
        frame_criar = ctk.CTkFrame(
            self,
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

        # 2. Alteração de Permissão
        frame_adm = ctk.CTkFrame(
            self,
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

        # 3. Remoção de Usuário
        frame_del_usr = ctk.CTkFrame(
            self,
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
        JanelaCadastroUsuario(self, on_user_created=self.func_atualizar_lista_usuarios_adm)

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
            self.app.set_status(
                f"✅ Permissão de '{usuario_alvo}' alterada para '{novo_role}'.",
                COR_TEXTO_VERDE,
            )
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.app.set_status("❌ Falha ao alterar permissão.", "#ef4444")

    def func_remover_usuario(self):
        usuario_alvo = self.combo_del_usuario.get()
        if not usuario_alvo:
            return

        sucesso, msg = deletar_usuario(usuario_alvo)
        if sucesso:
            self.app.set_status(f"✅ {msg}", COR_TEXTO_VERDE)
            self.func_atualizar_lista_usuarios_adm()
        else:
            self.app.set_status(f"❌ {msg}", "#ef4444")
