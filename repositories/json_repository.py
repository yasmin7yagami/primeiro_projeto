import json
import os
from typing import Dict, List, Optional
from config import NOME_ARQUIVO_ATIVOS
from models import Ativo, AtivoFactory
from repositories.base_repository import IAtivoRepository


class JsonAtivoRepository(IAtivoRepository):
    """Implementação do repositório com persistência em arquivo JSON no formato Array de Objetos.
    
    Atende ao Requisito 2 da Tabela 1:
    'Cada ativo deve ser armazenado em um arquivo no formato JSON constituído por um array (lista) de objetos JSON.'
    """

    def __init__(self, caminho_arquivo: str = NOME_ARQUIVO_ATIVOS):
        self.caminho_arquivo = caminho_arquivo
        self._cache: Dict[int, Ativo] = {}
        self._carregar()

    def _carregar(self):
        """Lê os dados do arquivo JSON e reconstrói as instâncias de Ativo/Equipamento."""
        self._cache.clear()
        if not os.path.exists(self.caminho_arquivo):
            return

        try:
            with open(self.caminho_arquivo, "r", encoding="utf-8") as f:
                conteudo = json.load(f)

                if isinstance(conteudo, list):
                    # Formato oficial do Trabalho 2: Array de objetos JSON
                    for item in conteudo:
                        id_num = int(item.get("id_ativo", item.get("id", 0)))
                        if id_num:
                            self._cache[id_num] = AtivoFactory.from_dict(id_num, item)
                elif isinstance(conteudo, dict):
                    # Compatibilidade retroativa com formato chave-valor
                    for k, v in conteudo.items():
                        id_num = int(k)
                        self._cache[id_num] = AtivoFactory.from_dict(id_num, v)
        except (json.JSONDecodeError, OSError) as e:
            print(f"⚠️ Erro ao carregar repositório JSON: {e}")
            self._cache = {}

    def _salvar_arquivo(self) -> bool:
        """Persiste os dados em disco como um ARRAY (lista) de objetos JSON com gravação atômica."""
        arquivo_temp = f"{self.caminho_arquivo}.tmp"
        try:
            # Requisito 2: Salvar como array (lista) de objetos JSON
            lista_ativos: List[dict] = [ativo.to_dict() for ativo in self._cache.values()]

            with open(arquivo_temp, "w", encoding="utf-8") as f:
                json.dump(lista_ativos, f, indent=4, ensure_ascii=False)

            os.replace(arquivo_temp, self.caminho_arquivo)
            return True
        except Exception as e:
            print(f"⚠️ Erro na escrita atômica do repositório JSON: {e}")
            if os.path.exists(arquivo_temp):
                try:
                    os.remove(arquivo_temp)
                except OSError:
                    pass
            return False

    def listar_todos(self) -> Dict[int, Ativo]:
        return dict(self._cache)

    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        return self._cache.get(int(id_ativo))

    def salvar(self, ativo: Ativo) -> bool:
        self._cache[ativo.id_ativo] = ativo
        return self._salvar_arquivo()

    def remover(self, id_ativo: int) -> bool:
        id_num = int(id_ativo)
        if id_num in self._cache:
            del self._cache[id_num]
            return self._salvar_arquivo()
        return False

    def existe(self, id_ativo: int) -> bool:
        return int(id_ativo) in self._cache
