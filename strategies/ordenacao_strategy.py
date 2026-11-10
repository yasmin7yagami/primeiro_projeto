from abc import ABC, abstractmethod
from typing import Callable, List
from models import Ativo


class IOrdenacaoStrategy(ABC):
    """Interface Abstrata para Estratégias de Ordenação de Ativos (Padrão Strategy - S4_03)."""

    @abstractmethod
    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        """Aplica a regra de ordenação sobre a lista de ativos."""
        pass


class OrdenacaoPorIdStrategy(IOrdenacaoStrategy):
    """Estratégia que ordena os ativos crescentemente pelo ID numérico."""

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: a.id_ativo)


class OrdenacaoPorHostnameStrategy(IOrdenacaoStrategy):
    """Estratégia que ordena os ativos alfabeticamente pelo Hostname."""

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: a.hostname.lower())


class OrdenacaoPorCriticidadeStrategy(IOrdenacaoStrategy):
    """Estratégia que prioriza ativos com mais vulnerabilidades (maior risco primeiro)."""

    def ordenar(self, ativos: List[Ativo]) -> List[Ativo]:
        return sorted(ativos, key=lambda a: len(a.vulnerabilidades), reverse=True)


# =====================================================================
# Implementação alternativa com Funções de Primeira Classe (Requisito 5 de S4_03)
# =====================================================================
def ordenar_ativos_funcional(
    ativos: List[Ativo], chave_ordenacao: Callable[[Ativo], any], reverso: bool = False
) -> List[Ativo]:
    """Ordena ativos utilizando uma função de primeira classe em vez de classes concretas."""
    return sorted(ativos, key=chave_ordenacao, reverse=reverso)
