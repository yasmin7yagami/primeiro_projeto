from models import Computador, RoteadorSwitch, Servidor
from strategies import (
    OrdenacaoPorCriticidadeStrategy,
    OrdenacaoPorHostnameStrategy,
    OrdenacaoPorIdStrategy,
    ordenar_ativos_funcional,
)

def test_estrategias_de_ordenacao():
    ativos = [
        Servidor(30, "zeta-srv", "Admin", "DC", vulnerabilidades=["CVE-1", "CVE-2"]),
        Computador(10, "alpha-pc", "Admin", "Sala 1", vulnerabilidades=[]),
        RoteadorSwitch(20, "beta-sw", "Admin", "Rack", vulnerabilidades=["CVE-3"]),
    ]

    por_id = OrdenacaoPorIdStrategy().ordenar(ativos)
    assert [a.id_ativo for a in por_id] == [10, 20, 30]

    por_host = OrdenacaoPorHostnameStrategy().ordenar(ativos)
    assert [a.hostname for a in por_host] == ["alpha-pc", "beta-sw", "zeta-srv"]

    por_crit = OrdenacaoPorCriticidadeStrategy().ordenar(ativos)
    assert [a.id_ativo for a in por_crit] == [30, 20, 10]

    por_id_func = ordenar_ativos_funcional(ativos, lambda a: a.id_ativo)
    assert [a.id_ativo for a in por_id_func] == [10, 20, 30]
