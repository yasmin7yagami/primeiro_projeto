from typing import Dict, List, Optional
from models import Ativo, AtivoFactory
from repositories import IAtivoRepository, JsonAtivoRepository
from strategies import IOrdenacaoStrategy, OrdenacaoPorIdStrategy
from utils import sanitizar_texto, validar_hostname, validar_id


class AssetService:
    """Camada de Serviço para Ativos de TI (Aplica DIP do SOLID: depende de IAtivoRepository)."""

    def __init__(self, repositorio: Optional[IAtivoRepository] = None):
        # Injeção de Dependência: Permite alternar entre JsonAtivoRepository e MemoriaAtivoRepository
        self.repositorio: IAtivoRepository = (
            repositorio if repositorio is not None else JsonAtivoRepository()
        )

    def obter_base_ativos(self) -> Dict[int, Ativo]:
        """Retorna o dicionário com todos os ativos gerenciados."""
        return self.repositorio.listar_todos()

    def obter_ativo(self, id_ativo: int) -> Optional[Ativo]:
        """Busca um ativo por seu ID."""
        return self.repositorio.obter_por_id(id_ativo)

    def cadastrar_ativo(
        self, id_str: str, hostname_bruto: str, responsavel_bruto: str, localizacao_bruto: str, tipo: str
    ):
        """Valida regras de negócio e persiste o novo ativo usando o AtivoFactory."""
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if self.repositorio.existe(res_id):
            return False, f"O ID {res_id} já existe!"

        if not validar_hostname(hostname_bruto):
            return False, "Hostname inválido! Use letras, números, hífen ou ponto (máx. 63 caracteres)."

        novo_ativo = AtivoFactory.criar_ativo(
            id_ativo=res_id,
            hostname=sanitizar_texto(hostname_bruto),
            responsavel=sanitizar_texto(responsavel_bruto),
            localizacao=sanitizar_texto(localizacao_bruto),
            tipo=tipo,
            vulnerabilidades=[],
        )

        sucesso = self.repositorio.salvar(novo_ativo)
        if sucesso:
            return True, f"Novo Ativo {res_id} registrado com sucesso!"
        return False, "Falha ao gravar ativo no repositório."

    def atualizar_ativo(
        self, id_str: str, hostname_bruto: str, responsavel_bruto: str, localizacao_bruto: str, tipo: str
    ):
        """Atualiza um ativo existente no repositório preservando vulnerabilidades."""
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        ativo = self.repositorio.obter_por_id(res_id)
        if not ativo:
            return False, "O ativo informado não existe!"

        if not validar_hostname(hostname_bruto):
            return False, "Hostname inválido! Use letras, números, hífen ou ponto (máx. 63 caracteres)."

        vulnerabilidades_existentes = list(ativo.vulnerabilidades)

        if ativo.tipo != tipo:
            ativo_atualizado = AtivoFactory.criar_ativo(
                id_ativo=res_id,
                hostname=sanitizar_texto(hostname_bruto),
                responsavel=sanitizar_texto(responsavel_bruto),
                localizacao=sanitizar_texto(localizacao_bruto),
                tipo=tipo,
                vulnerabilidades=vulnerabilidades_existentes,
            )
        else:
            ativo.hostname = sanitizar_texto(hostname_bruto)
            ativo.responsavel = sanitizar_texto(responsavel_bruto)
            ativo.localizacao = sanitizar_texto(localizacao_bruto)
            ativo_atualizado = ativo

        sucesso = self.repositorio.salvar(ativo_atualizado)
        if sucesso:
            return True, f"Ativo {res_id} atualizado com sucesso!"
        return False, "Falha ao atualizar ativo no repositório."

    def deletar_ativo(self, id_str: str):
        """Remove o ativo do repositório."""
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if not self.repositorio.existe(res_id):
            return False, "Ativo não encontrado!"

        sucesso = self.repositorio.remover(res_id)
        if sucesso:
            return True, f"Ativo {res_id} removido com sucesso!"
        return False, "Falha ao remover ativo do repositório."

    def vincular_cve_ao_ativo(self, id_str: str, cve_code: str):
        """Adiciona uma CVE ao ativo via método seguro de encapsulamento."""
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        ativo = self.repositorio.obter_por_id(res_id)
        if not ativo:
            return False, "ID de ativo inválido ou não encontrado!"

        cve_limpo = cve_code.strip().upper()
        if not ativo.adicionar_vulnerabilidade(cve_limpo):
            return False, "Esta CVE já está vinculada a este ativo."

        sucesso = self.repositorio.salvar(ativo)
        if sucesso:
            return True, f"{cve_limpo} vinculada ao Ativo ID {res_id}!"
        return False, "Falha ao persistir vinculação de vulnerabilidade."

    def ordenar_ativos(self, estrategia: Optional[IOrdenacaoStrategy] = None) -> List[Ativo]:
        """Aplica uma estratégia de ordenação (Strategy Pattern) sobre os ativos cadastrados."""
        if estrategia is None:
            estrategia = OrdenacaoPorIdStrategy()
        ativos = list(self.repositorio.listar_todos().values())
        return estrategia.ordenar(ativos)


# =====================================================================
# Instância global padrão e funções delegadas para compatibilidade direta
# =====================================================================
_servico_padrao = AssetService()


def obter_base_ativos() -> Dict[int, Ativo]:
    return _servico_padrao.obter_base_ativos()


def obter_ativo(id_ativo: int) -> Optional[Ativo]:
    return _servico_padrao.obter_ativo(id_ativo)


def cadastrar_ativo(id_str, hostname, responsavel, localizacao, tipo):
    return _servico_padrao.cadastrar_ativo(id_str, hostname, responsavel, localizacao, tipo)


def atualizar_ativo(id_str, hostname, responsavel, localizacao, tipo):
    return _servico_padrao.atualizar_ativo(id_str, hostname, responsavel, localizacao, tipo)


def deletar_ativo(id_str):
    return _servico_padrao.deletar_ativo(id_str)


def vincular_cve_ao_ativo(id_str, cve_code):
    return _servico_padrao.vincular_cve_ao_ativo(id_str, cve_code)


def salvar_dados_ativos():
    if isinstance(_servico_padrao.repositorio, JsonAtivoRepository):
        return _servico_padrao.repositorio._salvar_arquivo()
    return True


def carregar_dados_ativos():
    # Recarrega o repositório JSON padrão
    if isinstance(_servico_padrao.repositorio, JsonAtivoRepository):
        _servico_padrao.repositorio._carregar()
    return _servico_padrao.obter_base_ativos()
