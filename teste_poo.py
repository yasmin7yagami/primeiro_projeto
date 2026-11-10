import os
import unittest
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
from services.asset_service import (
    cadastrar_ativo,
    carregar_dados_ativos,
    deletar_ativo,
    obter_ativo,
    salvar_dados_ativos,
    vincular_cve_ao_ativo,
)


class TestesModelagemPOO(unittest.TestCase):
    """Suíte de testes para validação dos requisitos de POO (S3_01) e Persistência (S4_04)."""

    def test_heranca_e_isinstance(self):
        """Verifica se todas as subclasses herdam corretamente da classe base Ativo."""
        servidor = Servidor(1, "srv-web", "Carlos", "DC-1")
        roteador = RoteadorSwitch(2, "sw-core", "Ana", "Rack-A")
        computador = Computador(3, "pc-dev", "Mariana", "TI")
        impressora = Impressora(4, "imp-laser", "Suporte", "RH")

        self.assertIsInstance(servidor, Ativo)
        self.assertIsInstance(roteador, Ativo)
        self.assertIsInstance(computador, Ativo)
        self.assertIsInstance(impressora, Ativo)

    def test_polimorfismo_exibir_detalhes(self):
        """Testa o comportamento polimórfico do método exibir_detalhes()."""
        ativos = [
            Servidor(1, "srv-db", "Admin", "DC"),
            RoteadorSwitch(2, "sw-01", "Admin", "Rack"),
            Computador(3, "not-01", "Admin", "Sala 2"),
            Impressora(4, "imp-01", "Admin", "Recepção"),
        ]

        # Percorrendo lista heterogênea polimorficamente
        detalhes = [a.exibir_detalhes() for a in ativos]

        self.assertIn("[Servidor]", detalhes[0])
        self.assertIn("[Roteador/Switch]", detalhes[1])
        self.assertIn("[Computador]", detalhes[2])
        self.assertIn("[Impressora]", detalhes[3])

    def test_encapsulamento_vulnerabilidades(self):
        """Testa adição e remoção de vulnerabilidades garantindo integridade dos dados."""
        servidor = Servidor(10, "srv-teste", "Admin", "Lab")
        self.assertEqual(len(servidor.vulnerabilidades), 0)

        # Adiciona CVE
        sucesso = servidor.adicionar_vulnerabilidade("CVE-2021-44228")
        self.assertTrue(sucesso)
        self.assertIn("CVE-2021-44228", servidor.vulnerabilidades)

        # Tenta duplicar CVE
        duplicou = servidor.adicionar_vulnerabilidade("CVE-2021-44228")
        self.assertFalse(duplicou)
        self.assertEqual(len(servidor.vulnerabilidades), 1)

        # Remove CVE
        removeu = servidor.remover_vulnerabilidade("CVE-2021-44228")
        self.assertTrue(removeu)
        self.assertEqual(len(servidor.vulnerabilidades), 0)

    def test_factory_e_serializacao(self):
        """Testa a reconstrução de instâncias usando AtivoFactory.from_dict() e to_dict()."""
        dados_originais = {
            "id_ativo": 101,
            "hostname": "firewall-edge",
            "responsavel": "Yasmin",
            "localizacao": "Borda",
            "tipo": TipoAtivo.ROTEADORES_SWITCHES.value,
            "vulnerabilidades": ["CVE-2024-9999"],
            "qtd_portas": 48,
        }

        # Instanciação via Factory
        ativo = AtivoFactory.from_dict(101, dados_originais)

        self.assertIsInstance(ativo, RoteadorSwitch)
        self.assertEqual(ativo.hostname, "firewall-edge")
        self.assertEqual(ativo.qtd_portas, 48)

        # Serialização de volta para dict
        dict_gerado = ativo.to_dict()
        self.assertEqual(dict_gerado["tipo"], TipoAtivo.ROTEADORES_SWITCHES.value)
        self.assertEqual(dict_gerado["vulnerabilidades"], ["CVE-2024-9999"])

    def test_vulnerabilidade_classe(self):
        """Testa a classe auxiliar de Vulnerabilidade."""
        vuln = Vulnerabilidade("cve-2023-1234", cvss=7.5, severidade="Alta", descricao="Falha X")
        self.assertEqual(vuln.cve, "CVE-2023-1234")
        self.assertEqual(vuln.cvss, 7.5)

        dict_v = vuln.to_dict()
        recriada = Vulnerabilidade.from_dict(dict_v)
        self.assertEqual(recriada.cve, "CVE-2023-1234")


if __name__ == "__main__":
    unittest.main()
