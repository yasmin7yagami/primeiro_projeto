import pytest
from models import Computador, Impressora, RoteadorSwitch, Servidor
from repositories import MemoriaAtivoRepository
from services.risco_service import RiscoLinearService

def test_cenario_resolvido_a_mao():
    repo = MemoriaAtivoRepository()

    e1 = Servidor(101, "srv-web", "Carlos", "DC-1", vulnerabilidades=["CVE-2021-44228"])
    e2 = Servidor(102, "srv-db", "Ana", "DC-1", vulnerabilidades=["CVE-2022-22965"])
    e3 = RoteadorSwitch(103, "sw-borda", "TI", "Rack-A", vulnerabilidades=[])

    assert e1.adicionar_dependencia(102, 0.30) is True
    assert e3.adicionar_dependencia(101, 0.20) is True

    repo.salvar(e1)
    repo.salvar(e2)
    repo.salvar(e3)

    severidades = {
        "CVE-2021-44228": 10.0,
        "CVE-2022-22965": 8.0,
    }

    service = RiscoLinearService(repositorio=repo)
    res = service.calcular_risco(severidades_cve=severidades, aplicar_polimorfismo=True)

    assert res.sucesso is True
    assert res.invertivel is True
    assert res.determinante > 0.0

    assert pytest.approx(res.vetor_b[0], 0.001) == 12.5
    assert pytest.approx(res.vetor_b[1], 0.001) == 10.0
    assert pytest.approx(res.vetor_b[2], 0.001) == 0.0

    assert pytest.approx(res.vetor_x[0], 0.001) == 15.5
    assert pytest.approx(res.vetor_x[1], 0.001) == 10.0
    assert pytest.approx(res.vetor_x[2], 0.001) == 3.1

def test_polimorfismo_pondera_risco_proprio():
    repo = MemoriaAtivoRepository()

    servidor = Servidor(1, "srv-app", "Admin", "DC", vulnerabilidades=["CVE-2023-1111"])
    impressora = Impressora(2, "imp-rh", "Admin", "Sala 1", vulnerabilidades=["CVE-2023-1111"])

    repo.salvar(servidor)
    repo.salvar(impressora)

    service = RiscoLinearService(repositorio=repo)
    res = service.calcular_risco(severidades_cve={"CVE-2023-1111": 10.0}, aplicar_polimorfismo=True)

    assert res.sucesso is True
    assert res.vetor_b[0] == 12.5
    assert res.vetor_b[1] == 5.0
    assert res.vetor_b[0] > res.vetor_b[1]

def test_tabela_detalhada_consulta_aplicacao():
    repo = MemoriaAtivoRepository()
    e1 = Computador(10, "pc-analista", "Yasmin", "SOC", vulnerabilidades=["CVE-2020-0001"])
    repo.salvar(e1)

    service = RiscoLinearService(repositorio=repo)
    res = service.calcular_risco(severidades_cve={"CVE-2020-0001": 6.0})

    assert len(res.tabela_detalhada) == 1
    item = res.tabela_detalhada[0]
    assert item["id"] == 10
    assert item["hostname"] == "pc-analista"
    assert "risco_proprio" in item
    assert "risco_efetivo" in item
    assert item["risco_proprio"] == pytest.approx(6.0 * 0.85, 0.001)
