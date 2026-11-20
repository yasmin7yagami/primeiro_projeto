import json
import logging
import os
import tempfile
import threading
from typing import Dict, List, Optional
from config import NOME_ARQUIVO_ATIVOS
from models import Ativo, AtivoFactory
from repositories.base_repository import IAtivoRepository
from utils import normalizar_hostname

class JsonAtivoRepository(IAtivoRepository):

    def __init__(self, caminho_arquivo: str = NOME_ARQUIVO_ATIVOS):
        self.caminho_arquivo = caminho_arquivo
        self._lock = threading.RLock()
        self._cache: Dict[int, Ativo] = {}
        self._carregar()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def _carregar(self):
        with self._lock:
            self._cache.clear()
            if not os.path.exists(self.caminho_arquivo):
                return

            try:
                with open(self.caminho_arquivo, "r", encoding="utf-8-sig") as f:
                    conteudo = json.load(f)

                    if isinstance(conteudo, list):
                        for item in conteudo:
                            id_num = int(item.get("id_ativo", item.get("id", 0)))
                            if id_num:
                                self._cache[id_num] = AtivoFactory.from_dict(id_num, item)
                    elif isinstance(conteudo, dict):
                        for k, v in conteudo.items():
                            id_num = int(k)
                            self._cache[id_num] = AtivoFactory.from_dict(id_num, v)
            except (json.JSONDecodeError, OSError, ValueError) as e:
                logging.error(f"⚠️ Erro ao carregar repositório JSON: {e}")
                self._cache = {}

    def _salvar_arquivo(self) -> bool:
        with self._lock:
            diretorio = os.path.dirname(os.path.abspath(self.caminho_arquivo))
            os.makedirs(diretorio, exist_ok=True)
            arquivo_temp = None
            try:
                lista_ativos: List[dict] = [ativo.to_dict() for ativo in self._cache.values()]

                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=diretorio,
                    prefix=".ativos_",
                    suffix=".tmp",
                    delete=False,
                ) as f:
                    arquivo_temp = f.name
                    json.dump(lista_ativos, f, indent=4, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())

                os.replace(arquivo_temp, self.caminho_arquivo)
                return True
            except Exception as e:
                logging.error(f"⚠️ Erro na escrita atômica do repositório JSON: {e}")
                if arquivo_temp and os.path.exists(arquivo_temp):
                    try:
                        os.remove(arquivo_temp)
                    except OSError:
                        pass
                return False

    def listar_todos(self) -> Dict[int, Ativo]:
        with self._lock:
            return dict(self._cache)

    def obter_por_id(self, id_ativo: int) -> Optional[Ativo]:
        with self._lock:
            return self._cache.get(int(id_ativo))

    def salvar(self, ativo: Ativo) -> bool:
        with self._lock:
            self._cache[ativo.id_ativo] = ativo
            return self._salvar_arquivo()

    def remover(self, id_ativo: int) -> bool:
        with self._lock:
            id_num = int(id_ativo)
            if id_num in self._cache:
                del self._cache[id_num]
                return self._salvar_arquivo()
            return False

    def existe(self, id_ativo: int) -> bool:
        with self._lock:
            return int(id_ativo) in self._cache

    def existe_hostname(self, hostname: str, ignorar_id: Optional[int] = None) -> bool:
        alvo = normalizar_hostname(hostname)
        if not alvo:
            return False
        with self._lock:
            for id_atual, ativo in self._cache.items():
                if ignorar_id is not None and id_atual == int(ignorar_id):
                    continue
                if normalizar_hostname(ativo.hostname) == alvo:
                    return True
            return False
