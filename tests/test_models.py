import pytest
from models import (
    Ativo,
    AtivoFactory,
    Computador,
    Impressora,
    RoteadorSwitch,
    Servidor,
    TipoAtivo,
    Vulnerabilidade,
)


def test_instanciacao_subclasses_heranca():
    servidor = Servidor(1, "srv-01", "Admin", "Sala A")
    roteador = RoteadorSwitch(2, "sw-01", "Admin", "Sala B")
    computador = Computador(3, "pc-01", "Admin", "Sala C")
    impressora = Impressora(4, "imp-01", "Admin", "Sala D")

    assert isinstance(servidor, Ativo)
    assert isinstance(roteador, Ativo)
    assert isinstance(computador, Ativo)
    assert isinstance(impressora, Ativo)


def test_polimorfismo_exibir_detalhes():
    s = Servidor(10, "srv-cluster", "Admin", "DC")
    detalhes = s.exibir_detalhes()
    assert "[Servidor]" in detalhes
    assert "srv-cluster" in detalhes


def test_encapsulamento_adicao_vulnerabilidades():
    s = Servidor(10, "srv-teste", "Admin", "DC")
    assert s.adicionar_vulnerabilidade("CVE-2023-1234") is True
    assert "CVE-2023-1234" in s.vulnerabilidades
    # Não deve duplicar
    assert s.adicionar_vulnerabilidade("CVE-2023-1234") is False
    assert len(s.vulnerabilidades) == 1


def test_encapsulamento_remocao_vulnerabilidades():
    s = Servidor(10, "srv-teste", "Admin", "DC", vulnerabilidades=["CVE-2023-1234"])
    assert s.remover_vulnerabilidade("CVE-2023-1234") is True
    assert len(s.vulnerabilidades) == 0
    assert s.remover_vulnerabilidade("CVE-INEXISTENTE") is False


@pytest.mark.parametrize(
    "tipo, classe_esperada",
    [
        (TipoAtivo.SERVIDORES.value, Servidor),
        (TipoAtivo.ROTEADORES_SWITCHES.value, RoteadorSwitch),
        (TipoAtivo.COMPUTADORES.value, Computador),
        (TipoAtivo.IMPRESSORAS.value, Impressora),
    ],
)
def test_factory_method_criar_ativo(tipo, classe_esperada):
    ativo = AtivoFactory.criar_ativo(1, "host-test", "Resp", "Loc", tipo=tipo)
    assert isinstance(ativo, classe_esperada)


def test_serializacao_e_desserializacao_factory():
    dados = {
        "id_ativo": 55,
        "hostname": "firewall-gw",
        "responsavel": "Yasmin",
        "localizacao": "Borda",
        "tipo": TipoAtivo.ROTEADORES_SWITCHES.value,
        "vulnerabilidades": ["CVE-2021-44228"],
        "qtd_portas": 48,
    }
    ativo = AtivoFactory.from_dict(55, dados)
    assert isinstance(ativo, RoteadorSwitch)
    assert ativo.qtd_portas == 48

    d = ativo.to_dict()
    assert d["hostname"] == "firewall-gw"
    assert d["vulnerabilidades"] == ["CVE-2021-44228"]
