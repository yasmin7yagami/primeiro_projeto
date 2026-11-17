import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# Garante persistência e cópia dos dados iniciais para DATA_DIR caso ainda não existam
for nome_arquivo in ["base_ativos.json", "usuarios.json", "cves_salvas.json"]:
    origem = os.path.join(BASE_DIR, nome_arquivo)
    destino = os.path.join(DATA_DIR, nome_arquivo)
    if not os.path.exists(destino) and os.path.exists(origem):
        try:
            shutil.copy2(origem, destino)
        except OSError:
            pass

NOME_ARQUIVO_ATIVOS = os.path.join(DATA_DIR, "base_ativos.json")
NOME_ARQUIVO_USUARIOS = os.path.join(DATA_DIR, "usuarios.json")
NOME_ARQUIVO_CVES = os.path.join(DATA_DIR, "cves_salvas.json")
