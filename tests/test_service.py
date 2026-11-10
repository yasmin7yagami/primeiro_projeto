import pytest
from models import TipoAtivo


def test_cadastrar_ativo_com_sucesso(servico_com_memoria):
    sucesso, msg = servico_com_memoria.cadastrar_ativo(
        "103", "srv-backup", "Lucas", "DC-2", TipoAtivo.SERVIDORES.value
    )
    assert sucesso is True
    assert "registrado com sucesso" in msg
    assert servico_com_memoria.repositorio.existe(103) is True


@pytest.mark.parametrize(
    "id_str, hostname, valido_esperado, msg_esperada",
    [
        ("abc", "srv-db", False, "O ID deve conter apenas números"),
        ("0", "srv-db", False, "O ID deve ser entre 1 e 999999"),
        ("-5", "srv-db", False, "O ID deve conter apenas números"),
        ("101", "srv-existente", False, "já existe"),  # 101 já foi criado na fixture
        ("200", "host com espaco", False, "Hostname inválido"),
        ("200", "host_invalido_caractere!", False, "Hostname inválido"),
        ("200", "srv-valido-01.local", True, "registrado com sucesso"),
    ],
)
def test_validacao_regras_cadastro(
    servico_com_memoria, id_str, hostname, valido_esperado, msg_esperada
):
    sucesso, msg = servico_com_memoria.cadastrar_ativo(
        id_str, hostname, "Resp", "Loc", TipoAtivo.SERVIDORES.value
    )
    assert sucesso == valido_esperado
    assert msg_esperada in msg


def test_vincular_cve_ao_ativo(servico_com_memoria):
    sucesso, msg = servico_com_memoria.vincular_cve_ao_ativo("102", "CVE-2024-1111")
    assert sucesso is True

    ativo = servico_com_memoria.obter_ativo(102)
    assert "CVE-2024-1111" in ativo.vulnerabilidades


def test_deletar_ativo(servico_com_memoria):
    sucesso, msg = servico_com_memoria.deletar_ativo("101")
    assert sucesso is True
    assert servico_com_memoria.repositorio.existe(101) is False
