from abc import ABC, abstractmethod
from typing import Callable, List
from models import Ativo

class IOrdenacaoStrategy(ABC):

    @abstractmethod
    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        pass

class OrdenacaoPorIdStrategy(IOrdenacaoStrategy):

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: a.id_ativo)

class OrdenacaoPorHostnameStrategy(IOrdenacaoStrategy):

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: a.hostname.lower())

class OrdenacaoPorCriticidadeStrategy(IOrdenacaoStrategy):

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: len(a.vulnerabilidades), reverse=True)

def ordenar_ativos_funcional(
    ativos: List[Ativo], chave_ordenacao: Callable[[Ativo], any], reverso: bool = False
) -> List[Ativo]:
    return sorted(ativos, key=chave_ordenacao, reverse=reverso)
