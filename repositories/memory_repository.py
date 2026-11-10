from typing import Dict, Optional
from models import Ativo
from repositories.base_repository import IAtivoRepository


class MemoriaAtivoRepository(IAtivoRepository):
    """Implementação em memória do repositório de ativos (ideal para testes unitários rápidos)."""

    def __init__(self, dados_iniciais: Optional[Dict[int, Ativo]] = None):
        self._dados: Dict[int, Ativo] = dict(dados_iniciais) if dados_iniciais else {}

    def listar_todos(self) -> Dict[int, Ativo]:
        return dict(self._dados)

    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        return self._dados.get(int(id_ativo))

    def salvar(self, ativo: Ativo) -> bool:
        self._dados[ativo.id_ativo] = ativo
        return True

    def remover(self, id_ativo: int) -> bool:
        id_num = int(id_ativo)
        if id_num in self._dados:
            del self._dados[id_num]
            return True
        return False

    def existe(self, id_ativo: int) -> bool:
        return int(id_ativo) in self._dados
