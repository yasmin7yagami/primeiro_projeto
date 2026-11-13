from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional


class TipoAtivo(Enum):
    SERVIDORES = "Servidores"
    ROTEADORES_SWITCHES = "Roteadores/Switches"
    COMPUTADORES = "Computadores"
    IMPRESSORAS = "Impressoras"


class Vulnerabilidade:
    """Classe para representar uma vulnerabilidade associada aos ativos."""

    def __init__(
        self,
        cve: str,
        cvss: Optional[float] = None,
        severidade: Optional[str] = None,
        descricao: str = "",
    ):
        self._cve = cve.strip().upper()
        self._cvss = cvss
        self._severidade = severidade
        self._descricao = descricao

    @property
    def cve(self) -> str:
        return self._cve

    @property
    def cvss(self) -> Optional[float]:
        return self._cvss

    @property
    def severidade(self) -> Optional[str]:
        return self._severidade

    @property
    def descricao(self) -> str:
        return self._descricao

    def to_dict(self) -> Dict[str, Any]:
        """Serializa os dados da vulnerabilidade."""
        return {
            "cve": self._cve,
            "cvss": self._cvss,
            "severidade": self._severidade,
            "descricao": self._descricao,
        }

    @classmethod
    def from_dict(cls, dados: Any) -> "Vulnerabilidade":
        """Reconstrói uma instância de Vulnerabilidade a partir de uma string ou dicionário."""
        if isinstance(dados, str):
            return cls(cve=dados)
        elif isinstance(dados, dict):
            return cls(
                cve=dados.get("cve", dados.get("id", "")),
                cvss=dados.get("cvss"),
                severidade=dados.get("severidade"),
                descricao=dados.get("descricao", ""),
            )
        return cls(cve=str(dados))

    def __str__(self) -> str:
        return self._cve

    def __repr__(self) -> str:
        return f"Vulnerabilidade(cve='{self._cve}')"


class Ativo(ABC):
    """Classe Base Abstrata que define os atributos e comportamentos comuns a todos os ativos/equipamentos de TI.
    
    Atende ao Requisito 1 da Tabela 1 (derivação de objetos via POO).
    """

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        tipo: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
    ):
        self._id_ativo = int(id_ativo)
        self._hostname = hostname
        self._responsavel = responsavel
        self._localizacao = localizacao
        self._tipo = tipo
        self._vulnerabilidades = list(vulnerabilidades) if vulnerabilidades else []
        # Dependências de risco (Requisito 4): mapeia {id_outro_ativo: peso_A_ij}
        self._dependencias: Dict[int, float] = {}
        if dependencias:
            for k, v in dependencias.items():
                self.adicionar_dependencia(int(k), float(v))

    # Getters e Setters (Encapsulamento)
    @property
    def id_ativo(self) -> int:
        return self._id_ativo

    @property
    def hostname(self) -> str:
        return self._hostname

    @hostname.setter
    def hostname(self, valor: str):
        self._hostname = valor

    @property
    def responsavel(self) -> str:
        return self._responsavel

    @responsavel.setter
    def responsavel(self, valor: str):
        self._responsavel = valor

    @property
    def localizacao(self) -> str:
        return self._localizacao

    @localizacao.setter
    def localizacao(self, valor: str):
        self._localizacao = valor

    @property
    def tipo(self) -> str:
        return self._tipo

    @property
    def vulnerabilidades(self) -> List[str]:
        return list(self._vulnerabilidades)

    def adicionar_vulnerabilidade(self, cve: str) -> bool:
        """Adiciona uma nova CVE à lista de vulnerabilidades se não existir."""
        cve_limpo = cve.strip().upper()
        if cve_limpo not in self._vulnerabilidades:
            self._vulnerabilidades.append(cve_limpo)
            return True
        return False

    def remover_vulnerabilidade(self, cve: str) -> bool:
        """Remove uma CVE da lista de vulnerabilidades do ativo."""
        cve_limpo = cve.strip().upper()
        if cve_limpo in self._vulnerabilidades:
            self._vulnerabilidades.remove(cve_limpo)
            return True
        return False

    # Gestão de Dependências (Requisito 4 - Modelo de Álgebra Linear)
    def adicionar_dependencia(self, id_equipamento: int, fracao_risco: float) -> bool:
        """Adiciona ou atualiza uma dependência de risco transmitida de outro equipamento para este.
        
        Garante as regras do modelo linear:
        - A_ii = 0 (um equipamento não depende de si mesmo)
        - A_ij in [0, 1)
        - Soma das frações da linha < 1.0 (garante matriz I - A estritamente diagonal dominante e invertível)
        """
        id_eq = int(id_equipamento)
        if id_eq == self._id_ativo:
            return False  # A_ii = 0

        peso = float(fracao_risco)
        if not (0.0 <= peso < 1.0):
            return False

        # Verifica soma das dependências excluindo a dependência anterior deste ID (se houver atualização)
        soma_outras = sum(v for k, v in self._dependencias.items() if k != id_eq)
        if (soma_outras + peso) >= 1.0:
            return False

        self._dependencias[id_eq] = peso
        return True

    def remover_dependencia(self, id_equipamento: int) -> bool:
        """Remove a dependência em relação a outro equipamento."""
        id_eq = int(id_equipamento)
        if id_eq in self._dependencias:
            del self._dependencias[id_eq]
            return True
        return False

    def obter_dependencias(self) -> Dict[int, float]:
        """Retorna uma cópia das dependências registradas {id_alvo: fração_risco}."""
        return dict(self._dependencias)

    @abstractmethod
    def exibir_detalhes(self) -> str:
        """Método polimórfico obrigatório para descrever as especificidades do ativo."""
        pass

    @abstractmethod
    def fator_exposicao(self) -> float:
        """Método polimórfico que define o peso de exposição para ponderar o risco próprio no modelo linear."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Serialização para formato de dicionário compatível com o array JSON (Requisito 2)."""
        return {
            "id_ativo": self._id_ativo,
            "hostname": self._hostname,
            "responsavel": self._responsavel,
            "localizacao": self._localizacao,
            "tipo": self._tipo,
            "vulnerabilidades": list(self._vulnerabilidades),
            "dependencias": {int(k): float(v) for k, v in self._dependencias.items()},
        }

    # Métodos especiais para manter compatibilidade com acessos por chave
    def __getitem__(self, item: str):
        if item in ("id", "id_ativo"):
            return self._id_ativo
        if item == "hostname":
            return self._hostname
        if item == "responsavel":
            return self._responsavel
        if item == "localizacao":
            return self._localizacao
        if item == "tipo":
            return self._tipo
        if item == "vulnerabilidades":
            return self._vulnerabilidades
        if item == "dependencias":
            return self._dependencias
        raise KeyError(f"Chave '{item}' inválida para Ativo")

    def get(self, item: str, default=None):
        try:
            return self[item]
        except KeyError:
            return default


# Aliases explícitos conforme exigido pelo enunciado da 2ª Atividade Avaliativa (Tabela 1, Requisito 1)
Equipamento = Ativo
Equipamentos = Ativo


class Servidor(Ativo):
    """Subclasse de Ativo para servidores corporativos."""

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
        sistema_operacional: str = "Linux Server / Windows Server",
        funcao: str = "Serviços e Banco de Dados",
        **kwargs,
    ):
        super().__init__(
            id_ativo=id_ativo,
            hostname=hostname,
            responsavel=responsavel,
            localizacao=localizacao,
            tipo=TipoAtivo.SERVIDORES.value,
            vulnerabilidades=vulnerabilidades,
            dependencias=dependencias,
        )
        self.sistema_operacional = sistema_operacional
        self.funcao = funcao

    def exibir_detalhes(self) -> str:
        return (
            f"[Servidor] ID {self.id_ativo} | Hostname: {self.hostname} | "
            f"SO: {self.sistema_operacional} | Função: {self.funcao}"
        )

    def fator_exposicao(self) -> float:
        # Servidores expõem portas e serviços críticos na rede
        return 1.25

    def to_dict(self) -> Dict[str, Any]:
        dados = super().to_dict()
        dados["sistema_operacional"] = self.sistema_operacional
        dados["funcao"] = self.funcao
        return dados


class RoteadorSwitch(Ativo):
    """Subclasse de Ativo para equipamentos de conectividade de rede."""

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
        qtd_portas: int = 24,
        camada: str = "L2 / L3",
        **kwargs,
    ):
        super().__init__(
            id_ativo=id_ativo,
            hostname=hostname,
            responsavel=responsavel,
            localizacao=localizacao,
            tipo=TipoAtivo.ROTEADORES_SWITCHES.value,
            vulnerabilidades=vulnerabilidades,
            dependencias=dependencias,
        )
        self.qtd_portas = int(qtd_portas)
        self.camada = camada

    def exibir_detalhes(self) -> str:
        return (
            f"[Roteador/Switch] ID {self.id_ativo} | Hostname: {self.hostname} | "
            f"Portas: {self.qtd_portas} | Camada: {self.camada}"
        )

    def fator_exposicao(self) -> float:
        # Ativos centrais de roteamento e comutação de tráfego
        return 1.10

    def to_dict(self) -> Dict[str, Any]:
        dados = super().to_dict()
        dados["qtd_portas"] = self.qtd_portas
        dados["camada"] = self.camada
        return dados


class Computador(Ativo):
    """Subclasse de Ativo para estações de trabalho, computadores e notebooks."""

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
        sistema_operacional: str = "Windows 11 / Ubuntu Desktop",
        departamento: str = "Operações / TI",
        **kwargs,
    ):
        super().__init__(
            id_ativo=id_ativo,
            hostname=hostname,
            responsavel=responsavel,
            localizacao=localizacao,
            tipo=TipoAtivo.COMPUTADORES.value,
            vulnerabilidades=vulnerabilidades,
            dependencias=dependencias,
        )
        self.sistema_operacional = sistema_operacional
        self.departamento = departamento

    def exibir_detalhes(self) -> str:
        return (
            f"[Computador] ID {self.id_ativo} | Hostname: {self.hostname} | "
            f"Usuário: {self.responsavel} | Depto: {self.departamento}"
        )

    def fator_exposicao(self) -> float:
        # Estações de trabalho individuais
        return 0.85

    def to_dict(self) -> Dict[str, Any]:
        dados = super().to_dict()
        dados["sistema_operacional"] = self.sistema_operacional
        dados["departamento"] = self.departamento
        return dados


class Impressora(Ativo):
    """Subclasse de Ativo para impressoras de rede."""

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
        tipo_impressao: str = "Laser Corporativa",
        suporta_colorido: bool = True,
        **kwargs,
    ):
        super().__init__(
            id_ativo=id_ativo,
            hostname=hostname,
            responsavel=responsavel,
            localizacao=localizacao,
            tipo=TipoAtivo.IMPRESSORAS.value,
            vulnerabilidades=vulnerabilidades,
            dependencias=dependencias,
        )
        self.tipo_impressao = tipo_impressao
        self.suporta_colorido = suporta_colorido

    def exibir_detalhes(self) -> str:
        return (
            f"[Impressora] ID {self.id_ativo} | Hostname: {self.hostname} | "
            f"Tipo Impressão: {self.tipo_impressao} | Colorida: {'Sim' if self.suporta_colorido else 'Não'}"
        )

    def fator_exposicao(self) -> float:
        # Periférico com superfície de ataque restrita
        return 0.50

    def to_dict(self) -> Dict[str, Any]:
        dados = super().to_dict()
        dados["tipo_impressao"] = self.tipo_impressao
        dados["suporta_colorido"] = self.suporta_colorido
        return dados


class AtivoFactory:
    """Padrão Factory Method: cria dinamicamente a subclasse de Ativo correta a partir do tipo."""

    MAPA_CLASSES = {
        TipoAtivo.SERVIDORES.value: Servidor,
        "SERVIDORES": Servidor,
        TipoAtivo.ROTEADORES_SWITCHES.value: RoteadorSwitch,
        "ROTEADORES_SWITCHES": RoteadorSwitch,
        TipoAtivo.COMPUTADORES.value: Computador,
        "COMPUTADORES": Computador,
        TipoAtivo.IMPRESSORAS.value: Impressora,
        "IMPRESSORAS": Impressora,
    }

    @classmethod
    def criar_ativo(
        cls,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        tipo: str,
        vulnerabilidades: Optional[List[str]] = None,
        dependencias: Optional[Dict[int, float]] = None,
        **kwargs,
    ) -> Ativo:
        """Instancia a subclasse polimórfica com base no parâmetro 'tipo'."""
        classe_ativo = cls.MAPA_CLASSES.get(tipo, Servidor)
        return classe_ativo(
            id_ativo=id_ativo,
            hostname=hostname,
            responsavel=responsavel,
            localizacao=localizacao,
            vulnerabilidades=vulnerabilidades,
            dependencias=dependencias,
            **kwargs,
        )

    @classmethod
    def from_dict(cls, id_ativo: int, dados: Dict[str, Any]) -> Ativo:
        """Reconstrói uma instância de subclasse correta a partir de dados serializados em JSON."""
        tipo = dados.get("tipo", TipoAtivo.SERVIDORES.value)
        classe_ativo = cls.MAPA_CLASSES.get(tipo, Servidor)
        atributos_extras = {
            k: v
            for k, v in dados.items()
            if k not in [
                "id",
                "id_ativo",
                "hostname",
                "responsavel",
                "localizacao",
                "tipo",
                "vulnerabilidades",
                "dependencias",
            ]
        }
        return classe_ativo(
            id_ativo=int(id_ativo),
            hostname=dados.get("hostname", ""),
            responsavel=dados.get("responsavel", ""),
            localizacao=dados.get("localizacao", ""),
            vulnerabilidades=dados.get("vulnerabilidades", []),
            dependencias=dados.get("dependencias", {}),
            **atributos_extras,
        )


EquipamentoFactory = AtivoFactory
