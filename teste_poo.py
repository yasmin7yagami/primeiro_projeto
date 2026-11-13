import unittest
from models import (
    Ativo,
    AtivoFactory,
    Computador,
    Equipamento,
    Impressora,
    RoteadorSwitch,
    Servidor,
    TipoAtivo,
    Vulnerabilidade,
)


class TestesModelagemPOO(unittest.TestCase):
    """Suíte de testes para validação dos requisitos de POO (Requisito 1 - S3_01) e Persistência (Requisito 2)."""

    def test_heranca_e_isinstance(self):
        """Verifica se todas as subclasses herdam da classe base Equipamento/Ativo."""
        servidor = Servidor(1, "srv-web", "Carlos", "DC-1")
        roteador = RoteadorSwitch(2, "sw-core", "Ana", "Rack-A")
        computador = Computador(3, "pc-dev", "Mariana", "TI")
        impressora = Impressora(4, "imp-laser", "Suporte", "RH")

        self.assertIsInstance(servidor, Ativo)
        self.assertIsInstance(servidor, Equipamento)
        self.assertIsInstance(roteador, Ativo)
        self.assertIsInstance(computador, Ativo)
        self.assertIsInstance(impressora, Ativo)

    def test_polimorfismo_exibir_detalhes_e_fator_exposicao(self):
        """Testa o comportamento polimórfico de exibir_detalhes() e fator_exposicao()."""
        ativos = [
            Servidor(1, "srv-db", "Admin", "DC"),
            RoteadorSwitch(2, "sw-01", "Admin", "Rack"),
            Computador(3, "not-01", "Admin", "Sala 2"),
            Impressora(4, "imp-01", "Admin", "Recepção"),
        ]

        detalhes = [a.exibir_detalhes() for a in ativos]
        fatores = [a.fator_exposicao() for a in ativos]

        self.assertIn("[Servidor]", detalhes[0])
        self.assertIn("[Roteador/Switch]", detalhes[1])
        self.assertIn("[Computador]", detalhes[2])
        self.assertIn("[Impressora]", detalhes[3])

        # Polimorfismo no fator de exposição
        self.assertGreater(fatores[0], fatores[3])

    def test_encapsulamento_vulnerabilidades(self):
        """Testa adição e remoção de vulnerabilidades garantindo integridade dos dados."""
        servidor = Servidor(10, "srv-teste", "Admin", "Lab")
        self.assertEqual(len(servidor.vulnerabilidades), 0)

        # Adiciona CVE
        sucesso = servidor.adicionar_vulnerabilidade("CVE-2021-44228")
        self.assertTrue(sucesso)
        self.assertIn("CVE-2021-44228", servidor.vulnerabilidades)

        # Não permite duplicata
        duplicou = servidor.adicionar_vulnerabilidade("CVE-2021-44228")
        self.assertFalse(duplicou)
        self.assertEqual(len(servidor.vulnerabilidades), 1)

        # Remove CVE
        removeu = servidor.remover_vulnerabilidade("CVE-2021-44228")
        self.assertTrue(removeu)
        self.assertEqual(len(servidor.vulnerabilidades), 0)

    def test_gestao_dependencias_para_matriz_risco(self):
        """Testa o gerenciamento de dependências entre equipamentos (Requisito 4 / Álgebra Linear)."""
        servidor = Servidor(101, "srv-app", "Admin", "DC")
        self.assertTrue(servidor.adicionar_dependencia(102, 0.35))
        self.assertEqual(servidor.obter_dependencias().get(102), 0.35)

        # Não permite dependência de si mesmo (A_ii = 0)
        self.assertFalse(servidor.adicionar_dependencia(101, 0.5))

        # Não permite peso fora do intervalo [0, 1)
        self.assertFalse(servidor.adicionar_dependencia(103, 1.2))

        # Remoção de dependência
        self.assertTrue(servidor.remover_dependencia(102))
        self.assertNotIn(102, servidor.obter_dependencias())

    def test_factory_e_serializacao(self):
        """Testa a reconstrução de instâncias usando AtivoFactory.from_dict() e to_dict()."""
        dados_originais = {
            "id_ativo": 101,
            "hostname": "firewall-edge",
            "responsavel": "Yasmin",
            "localizacao": "Borda",
            "tipo": TipoAtivo.ROTEADORES_SWITCHES.value,
            "vulnerabilidades": ["CVE-2024-9999"],
            "dependencias": {"102": 0.25},
            "qtd_portas": 48,
        }

        ativo = AtivoFactory.from_dict(101, dados_originais)

        self.assertIsInstance(ativo, RoteadorSwitch)
        self.assertEqual(ativo.hostname, "firewall-edge")
        self.assertEqual(ativo.qtd_portas, 48)
        self.assertEqual(ativo.obter_dependencias().get(102), 0.25)

        # Serialização de volta para dict
        dict_gerado = ativo.to_dict()
        self.assertEqual(dict_gerado["tipo"], TipoAtivo.ROTEADORES_SWITCHES.value)
        self.assertEqual(dict_gerado["vulnerabilidades"], ["CVE-2024-9999"])
        self.assertEqual(dict_gerado["dependencias"], {102: 0.25})

    def test_vulnerabilidade_classe(self):
        """Testa a classe de valor para Vulnerabilidade."""
        vuln = Vulnerabilidade("cve-2023-1234", cvss=7.5, severidade="Alta", descricao="Falha X")
        self.assertEqual(vuln.cve, "CVE-2023-1234")
        self.assertEqual(vuln.cvss, 7.5)

        dict_v = vuln.to_dict()
        recriada = Vulnerabilidade.from_dict(dict_v)
        self.assertEqual(recriada.cve, "CVE-2023-1234")


if __name__ == "__main__":
    unittest.main()
