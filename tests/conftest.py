import os
import sys
import pytest

# Garante que a raiz do projeto esteja no path de importação dos testes
DIRETORIO_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if DIRETORIO_RAIZ not in sys.path:
    sys.path.insert(0, DIRETORIO_RAIZ)

from models import AtivoFactory, Servidor, RoteadorSwitch, Computador, Impressora
from repositories import MemoriaAtivoRepository, JsonAtivoRepository
from services.asset_service import AssetService


@pytest.fixture
def repositorio_memoria():
    """Fixture que fornece um repositório isolado em memória."""
    repo = MemoriaAtivoRepository()
    repo.salvar(Servidor(101, "srv-app", "Yasmin", "DC-1", vulnerabilidades=["CVE-2021-44228"]))
    repo.salvar(RoteadorSwitch(102, "sw-borda", "Carlos", "Rack 1"))
    return repo


@pytest.fixture
def servico_com_memoria(repositorio_memoria):
    """Fixture que injeta o repositório em memória no AssetService (DIP)."""
    return AssetService(repositorio=repositorio_memoria)


@pytest.fixture
def repositorio_json_temp(tmp_path):
    """Fixture que prepara um repositório JSON temporário isolado por teste usando tmp_path."""
    arquivo_temp = tmp_path / "base_teste.json"
    repo = JsonAtivoRepository(caminho_arquivo=str(arquivo_temp))
    return repo
