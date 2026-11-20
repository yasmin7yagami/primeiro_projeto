import threading
from typing import Dict, Optional
from models import Ativo
from repositories.base_repository import IAtivoRepository
from utils import normalizar_hostname

class MemoriaAtivoRepository(IAtivoRepository):

    def __init__(self, dados_iniciais: Optional[Dict[int, Ativo]] = None):
        self._lock = threading.RLock()
        self._dados: Dict[int, Ativo] = dict(dados_iniciais) if dados_iniciais else {}

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def listar_todos(self) -> Dict[int, Ativo]:
        with self._lock:
            return dict(self._dados)

    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        with self._lock:
            return self._dados.get(int(id_ativo))

    def salvar(self, ativo: Ativo) -> bool:
        with self._lock:
            self._dados[ativo.id_ativo] = ativo
            return True

    def remover(self, id_ativo: int) -> bool:
        with self._lock:
            id_num = int(id_ativo)
            if id_num in self._dados:
                del self._dados[id_num]
                return True
            return False

    def existe(self, id_ativo: int) -> bool:
        with self._lock:
            return int(id_ativo) in self._dados

    def existe_hostname(self, hostname: str, ignorar_id: Optional[int] = None) -> bool:
        alvo = normalizar_hostname(hostname)
        if not alvo:
            return False
        with self._lock:
            for id_atual, ativo in self._dados.items():
                if ignorar_id is not None and id_atual == int(ignorar_id):
                    continue
                if normalizar_hostname(ativo.hostname) == alvo:
                    return True
            return False
