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
