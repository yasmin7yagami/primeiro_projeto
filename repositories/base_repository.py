from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from models import Ativo

class IAtivoRepository(ABC):

    @abstractmethod
    def listar_todos(self) -> Dict[int, Ativo]:
        pass

    @abstractmethod
    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        pass

    @abstractmethod
    def salvar(self, ativo: Ativo) -> bool:
        pass

    @abstractmethod
    def remover(self, id_ativo: int) -> bool:
        pass

    @abstractmethod
    def existe(self, id_ativo: int) -> bool:
        pass

    @abstractmethod
    def existe_hostname(self, hostname: str, ignorar_id: Optional[int] = None) -> bool:
        pass
