import json
from models import Computador, Servidor, TipoAtivo
from repositories import JsonAtivoRepository, MemoriaAtivoRepository


def test_memoria_repository_crud():
    repo = MemoriaAtivoRepository()
    servidor = Servidor(1, "srv-01", "Admin", "Sala A")

    assert repo.salvar(servidor) is True
    assert repo.existe(1) is True
    assert repo.obter_por_id(1).hostname == "srv-01"

    assert repo.remover(1) is True
    assert repo.existe(1) is False


def test_json_repository_persistencia_e_recarga(tmp_path):
    arquivo_teste = tmp_path / "teste_ativos.json"
    repo1 = JsonAtivoRepository(caminho_arquivo=str(arquivo_teste))

    pc = Computador(
        id_ativo=201,
        hostname="pc-dev",
        responsavel="Yasmin",
        localizacao="Lab 2",
        vulnerabilidades=["CVE-2022-1234"],
        departamento="Segurança",
    )
    repo1.salvar(pc)

    # Recarrega a partir de uma nova instância lendo o mesmo arquivo
    repo2 = JsonAtivoRepository(caminho_arquivo=str(arquivo_teste))
    ativo_recuperado = repo2.obter_por_id(201)

    assert ativo_recuperado is not None
    assert isinstance(ativo_recuperado, Computador)
    assert ativo_recuperado.hostname == "pc-dev"
    assert ativo_recuperado.departamento == "Segurança"
    assert "CVE-2022-1234" in ativo_recuperado.vulnerabilidades


def test_json_repository_formato_array_json(tmp_path):
    """Garante atendimento ao Requisito 2: o arquivo gerado deve ser um array (lista) de objetos JSON."""
    arquivo_teste = tmp_path / "teste_formato_array.json"
    repo = JsonAtivoRepository(caminho_arquivo=str(arquivo_teste))

    s1 = Servidor(101, "srv-web", "Admin", "DC")
    s2 = Servidor(102, "srv-db", "Admin", "DC")
    s1.adicionar_dependencia(102, 0.25)

    repo.salvar(s1)
    repo.salvar(s2)

    # Lê o arquivo diretamente em disco e verifica se a raiz é uma lista
    with open(arquivo_teste, "r", encoding="utf-8") as f:
        dados = json.load(f)

    assert isinstance(dados, list)
    assert len(dados) == 2
    ids = [item["id_ativo"] for item in dados]
    assert 101 in ids
    assert 102 in ids

    # Verifica persistência das dependências
    item_101 = next(item for item in dados if item["id_ativo"] == 101)
    assert item_101["dependencias"] == {"102": 0.25}
