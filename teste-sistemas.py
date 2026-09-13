import unittest
import json
import os
from main import validar_cve

class TestesSistemaTI(unittest.TestCase):

    def setUp(self):
        """Prepara os dados antes de cada teste."""
        self.base_ativos = {
            101: {
                "hostname": "servidor-web",
                "responsavel": "Carlos",
                "localizacao": "Data Center",
                "tipo": "SERVIDORES",
                "vulnerabilidades": []
            }
        }
        self.arquivo_teste = "base_teste.json"

    def tearDown(self):
        """Limpa arquivos temporários após cada teste."""
        if os.path.exists(self.arquivo_teste):
            os.remove(self.arquivo_teste)

    # Testes de Validação
    def test_cve_valido(self):
        self.assertTrue(validar_cve("CVE-2024-1234"))

    def test_cve_invalido(self):
        self.assertFalse(validar_cve("INVALIDO-123"))

    # Testes de Dicionário (CRUD)
    def test_insercao_ativo(self):
        self.base_ativos[102] = {"hostname": "firewall"}
        self.assertIn(102, self.base_ativos)

    def test_remocao_ativo(self):
        self.base_ativos.pop(101)
        self.assertNotIn(101, self.base_ativos)

    # Teste de Persistência JSON
    def test_escrita_e_leitura_json(self):
        dados_salvar = {str(k): v for k, v in self.base_ativos.items()}
        with open(self.arquivo_teste, "w", encoding="utf-8") as f:
            json.dump(dados_salvar, f)

        with open(self.arquivo_teste, "r", encoding="utf-8") as f:
            dados_carregados = json.load(f)
            base_restaurada = {int(k): v for k, v in dados_carregados.items()}

        self.assertEqual(self.base_ativos, base_restaurada)

if __name__ == '__main__':
    unittest.main()