from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from models import Ativo


class IAtivoRepository(ABC):
    """Interface Abstrata do Repositório de Ativos (DIP - Dependency Inversion Principle).

    Define o contrato para persistência sem acoplamento a tecnologias específicas (JSON, SQLite, Memória).
    """

    @abstractmethod
    def listar_todos(self) -> Dict[int, Ativo]:
        """Retorna todos os ativos armazenados indexados pelo ID."""
        pass

    @abstractmethod
    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        """Busca um ativo específico pelo seu ID."""
        pass

    @abstractmethod
    def salvar(self, ativo: Ativo) -> bool:
        """Adiciona ou atualiza um ativo no repositório."""
        pass

    @abstractmethod
    def remover(self, id_ativo: int) -> bool:
        """Remove um ativo pelo seu ID."""
        pass

    @abstractmethod
    def existe(self, id_ativo: int) -> bool:
        """Verifica se um ativo com o ID especificado já existe."""
        pass
