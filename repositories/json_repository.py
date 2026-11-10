import json
import os
from typing import Dict, Optional
from config import NOME_ARQUIVO_ATIVOS
from models import Ativo, AtivoFactory
from repositories.base_repository import IAtivoRepository


class JsonAtivoRepository(IAtivoRepository):
    """Implementação do repositório com persistência em arquivo JSON e escrita atômica."""

    def __init__(self, caminho_arquivo: str = NOME_ARQUIVO_ATIVOS):
        self.caminho_arquivo = caminho_arquivo
        self._cache: Dict[int, Ativo] = {}
        self._carregar()

    def _carregar(self):
        """Lê os dados do arquivo JSON e reconstrói as instâncias de Ativo."""
        self._cache.clear()
        if not os.path.exists(self.caminho_arquivo):
            return

        try:
            with open(self.caminho_arquivo, "r", encoding="utf-8") as f:
                conteudo = json.load(f)

                if isinstance(conteudo, dict):
                    for k, v in conteudo.items():
                        id_num = int(k)
                        self._cache[id_num] = AtivoFactory.from_dict(id_num, v)
                elif isinstance(conteudo, list):
                    for item in conteudo:
                        id_num = int(item.get("id_ativo", item.get("id", 0)))
                        if id_num:
                            self._cache[id_num] = AtivoFactory.from_dict(id_num, item)
        except (json.JSONDecodeError, OSError) as e:
            print(f"⚠️ Erro ao carregar repositório JSON: {e}")
            self._cache = {}

    def _salvar_arquivo(self) -> bool:
        """Persiste os dados em disco usando gravação atômica (arquivo temporário + os.replace)."""
        arquivo_temp = f"{self.caminho_arquivo}.tmp"
        try:
            dados_serializados = {
                str(k): v.to_dict() for k, v in self._cache.items()
            }
            with open(arquivo_temp, "w", encoding="utf-8") as f:
                json.dump(dados_serializados, f, indent=4, ensure_ascii=False)

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
