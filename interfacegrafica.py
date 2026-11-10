import io
import os
import sys

# Garante que o diretório raiz do projeto esteja no caminho de importação do Python
DIRETORIO_RAIZ = os.path.dirname(os.path.abspath(__file__))
if DIRETORIO_RAIZ not in sys.path:
    sys.path.insert(0, DIRETORIO_RAIZ)

# Configuração para o terminal do Windows 🪟
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from config import inicializar_tema

# Configura o tema do CustomTkinter
inicializar_tema()

from ui.login_window import JanelaLogin
from ui.main_window import AplicacaoInventario


def iniciar_aplicacao():
    """Inicia o fluxo principal de autenticação e abertura do sistema."""

    def callback_login_sucesso(nome_usuario, role_usuario, login_id):
        app = AplicacaoInventario(
            nome_usuario, role_usuario, login_id, on_logout=iniciar_aplicacao
        )
        app.mainloop()

    login_app = JanelaLogin(callback_login_sucesso)
    login_app.mainloop()


if __name__ == "__main__":
    iniciar_aplicacao()
