from contextlib import nullcontext
from typing import Any, Dict, List, Optional
from models import Ativo, AtivoFactory
from repositories import IAtivoRepository, JsonAtivoRepository
from strategies import IOrdenacaoStrategy, OrdenacaoPorIdStrategy
from utils import sanitizar_texto, validar_cve, validar_hostname, validar_id

CAMPOS_EXTRAS_PERMITIDOS = {
    "sistema_operacional",
    "funcao",
    "qtd_portas",
    "camada",
    "departamento",
    "tipo_impressao",
    "suporta_colorido",
}

class AssetService:

    def __init__(self, repositorio: Optional[IAtivoRepository] = None):
        self.repositorio: IAtivoRepository = (
            repositorio if repositorio is not None else JsonAtivoRepository()
        )

    def _obter_lock(self):
        lock = getattr(self.repositorio, "lock", None)
        return lock if lock is not None else nullcontext()

    @staticmethod
    def _sanitizar_extras(atributos_extras: Dict[str, Any]) -> Dict[str, Any]:
        limpos: Dict[str, Any] = {}
        for chave, valor in atributos_extras.items():
            if chave not in CAMPOS_EXTRAS_PERMITIDOS:
                continue
            if valor is None or valor == "":
                continue
            if chave == "qtd_portas":
                try:
                    limpos[chave] = int(valor)
                except (TypeError, ValueError):
                    continue
            elif chave == "suporta_colorido":
                limpos[chave] = bool(valor)
            else:
                texto_limpo = sanitizar_texto(valor)
                if texto_limpo:
                    limpos[chave] = texto_limpo
        return limpos

    def obter_base_ativos(self) -> Dict[int, Ativo]:
        return self.repositorio.listar_todos()

    def obter_ativo(self, id_ativo: int) -> Optional[Ativo]:
        return self.repositorio.obter_por_id(id_ativo)

    def cadastrar_ativo(
        self,
        id_str: Any,
        hostname_bruto: str,
        responsavel_bruto: str,
        localizacao_bruto: str,
        tipo: str,
        vulnerabilidades: Optional[List[str]] = None,
        **atributos_extras,
    ):
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if not AtivoFactory.tipo_valido(tipo):
            return False, "Tipo de ativo inválido!"

        if not validar_hostname(hostname_bruto):
            return False, "Hostname inválido! Use letras, números, hífen ou ponto (máx. 63 caracteres)."

        hostname_limpo = sanitizar_texto(hostname_bruto, max_len=63)
        responsavel_limpo = sanitizar_texto(responsavel_bruto)
        localizacao_limpa = sanitizar_texto(localizacao_bruto)

        if not responsavel_limpo:
            return False, "O campo responsável é obrigatório."
        if not localizacao_limpa:
            return False, "O campo localização é obrigatório."

        vuls_validadas: List[str] = []
        if vulnerabilidades is not None:
            if not isinstance(vulnerabilidades, list):
                return False, "Lista de vulnerabilidades inválida."
            for cve in vulnerabilidades:
                if not validar_cve(cve):
                    return False, f"Formato de CVE inválido: '{cve}'. Use o padrão CVE-AAAA-NNNN."
                cve_norm = cve.strip().upper()
                if cve_norm in vuls_validadas:
                    return False, f"A CVE {cve_norm} está duplicada para este ativo."
                vuls_validadas.append(cve_norm)

        extras_limpos = self._sanitizar_extras(atributos_extras)

        with self._obter_lock():
            if self.repositorio.existe(res_id):
                return False, f"O ID {res_id} já existe!"

            if self.repositorio.existe_hostname(hostname_limpo):
                return False, f"Já existe um ativo cadastrado com o hostname '{hostname_limpo}'!"

            novo_ativo = AtivoFactory.criar_ativo(
                id_ativo=res_id,
                hostname=hostname_limpo,
                responsavel=responsavel_limpo,
                localizacao=localizacao_limpa,
                tipo=tipo,
                vulnerabilidades=vuls_validadas,
                **extras_limpos,
            )

            sucesso = self.repositorio.salvar(novo_ativo)
            if sucesso:
                return True, f"Novo Ativo {res_id} registrado com sucesso!"
            return False, "Falha ao gravar ativo no repositório."

    def atualizar_ativo(
        self,
        id_str: Any,
        hostname_bruto: str,
        responsavel_bruto: str,
        localizacao_bruto: str,
        tipo: str,
        **atributos_extras,
    ):
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if not AtivoFactory.tipo_valido(tipo):
            return False, "Tipo de ativo inválido!"

        if not validar_hostname(hostname_bruto):
            return False, "Hostname inválido! Use letras, números, hífen ou ponto (máx. 63 caracteres)."

        hostname_limpo = sanitizar_texto(hostname_bruto, max_len=63)
        responsavel_limpo = sanitizar_texto(responsavel_bruto)
        localizacao_limpa = sanitizar_texto(localizacao_bruto)

        if not responsavel_limpo:
            return False, "O campo responsável é obrigatório."
        if not localizacao_limpa:
            return False, "O campo localização é obrigatório."

        extras_limpos = self._sanitizar_extras(atributos_extras)

        with self._obter_lock():
            ativo = self.repositorio.obter_por_id(res_id)
            if not ativo:
                return False, "O ativo informado não existe!"

            if self.repositorio.existe_hostname(hostname_limpo, ignorar_id=res_id):
                return False, f"Já existe outro ativo cadastrado com o hostname '{hostname_limpo}'!"

            vulnerabilidades_existentes = list(ativo.vulnerabilidades)
            dependencias_existentes = dict(ativo.obter_dependencias())

            if ativo.tipo != tipo:
                ativo_atualizado = AtivoFactory.criar_ativo(
                    id_ativo=res_id,
                    hostname=hostname_limpo,
                    responsavel=responsavel_limpo,
                    localizacao=localizacao_limpa,
                    tipo=tipo,
                    vulnerabilidades=vulnerabilidades_existentes,
                    dependencias=dependencias_existentes,
                    **extras_limpos,
                )
            else:
                ativo.hostname = hostname_limpo
                ativo.responsavel = responsavel_limpo
                ativo.localizacao = localizacao_limpa
                for chave, valor in extras_limpos.items():
                    if hasattr(ativo, chave):
                        setattr(ativo, chave, valor)
                ativo_atualizado = ativo

            sucesso = self.repositorio.salvar(ativo_atualizado)
            if sucesso:
                return True, f"Ativo {res_id} atualizado com sucesso!"
            return False, "Falha ao atualizar ativo no repositório."

    def deletar_ativo(self, id_str: Any):
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        with self._obter_lock():
            if not self.repositorio.existe(res_id):
                return False, "Ativo não encontrado!"

            sucesso = self.repositorio.remover(res_id)
            if not sucesso:
                return False, "Falha ao remover ativo do repositório."

            for outro_ativo in self.repositorio.listar_todos().values():
                if outro_ativo.remover_dependencia(res_id):
                    self.repositorio.salvar(outro_ativo)

            return True, f"Ativo {res_id} removido com sucesso!"

    def vincular_cve_ao_ativo(self, id_str: Any, cve_code: str):
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if not validar_cve(cve_code):
            return False, "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)."

        cve_limpo = cve_code.strip().upper()

        with self._obter_lock():
            ativo = self.repositorio.obter_por_id(res_id)
            if not ativo:
                return False, "ID de ativo inválido ou não encontrado!"

            if not ativo.adicionar_vulnerabilidade(cve_limpo):
                return False, f"A CVE {cve_limpo} já está vinculada a este ativo."

            sucesso = self.repositorio.salvar(ativo)
            if sucesso:
                return True, f"{cve_limpo} vinculada ao Ativo ID {res_id}!"
            return False, "Falha ao persistir vinculação de vulnerabilidade."

    def desvincular_cve_do_ativo(self, id_str: Any, cve_code: str):
        valido, res_id = validar_id(id_str)
        if not valido:
            return False, f"Erro de Validação: {res_id}"

        if not isinstance(cve_code, str) or not cve_code.strip():
            return False, "Código CVE obrigatório."

        cve_limpo = cve_code.strip().upper()

        with self._obter_lock():
            ativo = self.repositorio.obter_por_id(res_id)
            if not ativo:
                return False, "Ativo não encontrado!"

            if not ativo.remover_vulnerabilidade(cve_limpo):
                return False, f"A CVE {cve_limpo} não está vinculada a este ativo."

            sucesso = self.repositorio.salvar(ativo)
            if sucesso:
                return True, f"{cve_limpo} removida do Ativo ID {res_id}!"
            return False, "Falha ao persistir remoção de vulnerabilidade."

    def adicionar_dependencia(self, id_origem_str: Any, id_alvo_str: Any, peso: Any):
        valido_orig, id_origem = validar_id(id_origem_str)
        if not valido_orig:
            return False, f"ID de origem inválido: {id_origem}"

        valido_alvo, id_alvo = validar_id(id_alvo_str)
        if not valido_alvo:
            return False, f"ID de destino inválido: {id_alvo}"

        try:
            peso_float = float(peso)
        except (TypeError, ValueError):
            return False, "Peso de dependência inválido."

        with self._obter_lock():
            ativo = self.repositorio.obter_por_id(id_origem)
            if not ativo:
                return False, "Ativo não encontrado."

            if not self.repositorio.existe(id_alvo):
                return False, f"O equipamento de destino (ID {id_alvo}) não existe."

            if not ativo.adicionar_dependencia(id_alvo, peso_float):
                return False, (
                    "Dependência inválida! Regras: A_ii = 0, peso em [0, 1) "
                    "e soma das dependências da linha < 1.0."
                )

            if self.repositorio.salvar(ativo):
                return True, "Dependência de risco registrada com sucesso!"
            return False, "Falha ao salvar dependência no repositório."

    def remover_dependencia(self, id_origem_str: Any, id_alvo_str: Any):
        valido_orig, id_origem = validar_id(id_origem_str)
        valido_alvo, id_alvo = validar_id(id_alvo_str)
        if not valido_orig or not valido_alvo:
            return False, "ID inválido."

        with self._obter_lock():
            ativo = self.repositorio.obter_por_id(id_origem)
            if ativo and ativo.remover_dependencia(id_alvo):
                if self.repositorio.salvar(ativo):
                    return True, "Dependência removida com sucesso!"
                return False, "Falha ao persistir remoção de dependência."
            return False, "Dependência não encontrada."

    def ordenar_ativos(self, estrategia: Optional[IOrdenacaoStrategy] = None) -> List[Ativo]:
        if estrategia is None:
            estrategia = OrdenacaoPorIdStrategy()
        ativos = list(self.repositorio.listar_todos().values())
        return estrategia.ordenar(ativos)

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

def desvincular_cve_do_ativo(id_str, cve_code):
    return _servico_padrao.desvincular_cve_do_ativo(id_str, cve_code)

def salvar_dados_ativos():
    if isinstance(_servico_padrao.repositorio, JsonAtivoRepository):
        return _servico_padrao.repositorio._salvar_arquivo()
    return True

def carregar_dados_ativos():
    if isinstance(_servico_padrao.repositorio, JsonAtivoRepository):
        _servico_padrao.repositorio._carregar()
    return _servico_padrao.obter_base_ativos()
