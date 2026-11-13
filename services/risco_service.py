import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
    TEM_NUMPY = True
except ImportError:
    np = None
    TEM_NUMPY = False

from models import Ativo
from repositories import IAtivoRepository, JsonAtivoRepository


@dataclass
class ResultadoAnaliseRisco:
    """Estrutura com os resultados completos da Análise de Risco por Álgebra Linear (Requisito 4)."""

    sucesso: bool
    mensagem: str
    equipamentos_ids: List[int] = field(default_factory=list)
    equipamentos_hostnames: List[str] = field(default_factory=list)
    vulnerabilidades_cves: List[str] = field(default_factory=list)
    matriz_M: List[List[int]] = field(default_factory=list)
    vetor_v: List[float] = field(default_factory=list)
    vetor_b: List[float] = field(default_factory=list)  # Risco próprio
    matriz_A: List[List[float]] = field(default_factory=list)  # Dependências
    matriz_I_A: List[List[float]] = field(default_factory=list)
    invertivel: bool = False
    determinante: float = 0.0
    numero_condicao: float = 0.0
    vetor_x: List[float] = field(default_factory=list)  # Risco efetivo
    tabela_detalhada: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sucesso": self.sucesso,
            "mensagem": self.mensagem,
            "invertivel": self.invertivel,
            "determinante": round(self.determinante, 6),
            "numero_condicao": round(self.numero_condicao, 4) if self.numero_condicao else None,
            "equipamentos_ids": self.equipamentos_ids,
            "vulnerabilidades_cves": self.vulnerabilidades_cves,
            "risco_proprio_b": [round(val, 4) for val in self.vetor_b],
            "risco_efetivo_x": [round(val, 4) for val in self.vetor_x],
            "tabela": self.tabela_detalhada,
        }


class RiscoLinearService:
    """Serviço de Análise de Risco Baseado em Álgebra Linear (Requisito 4).
    
    Implementa o modelo linear:
      x = b + A x  <=>  (I - A) x = b
    
    Elementos:
      - n equipamentos, m vulnerabilidades.
      - M in {0, 1}^(n x m): Matriz de incidência (equipamento i afetado por CVE j).
      - v in R^m: Vetor de severidade das vulnerabilidades (notas CVSS).
      - b = M v in R^n: Risco próprio de cada equipamento (ponderado pelo fator polimórfico).
      - A in R^(n x n): Matriz de dependências (A_ij in [0, 1), A_ii = 0).
      - x in R^n: Risco efetivo resolvendo o sistema linear (I - A) x = b.
    """

    def __init__(self, repositorio: Optional[IAtivoRepository] = None):
        self.repositorio = repositorio if repositorio is not None else JsonAtivoRepository()

    # =========================================================================
    # ÁLGEBRA LINEAR PURA (Fallback quando NumPy não estiver instalado)
    # =========================================================================
    @staticmethod
    def _calcular_determinante(matriz: List[List[float]]) -> float:
        """Calcula o determinante de uma matriz quadrada via eliminação de Gauss."""
        n = len(matriz)
        if n == 0:
            return 1.0
        # Cópia para não alterar o original
        a = [row[:] for row in matriz]
        det = 1.0

        for i in range(n):
            pivo = i
            for r in range(i + 1, n):
                if abs(a[r][i]) > abs(a[pivo][i]):
                    pivo = r
            if pivo != i:
                a[i], a[pivo] = a[pivo], a[i]
                det = -det

            if abs(a[i][i]) < 1e-12:
                return 0.0

            det *= a[i][i]
            for r in range(i + 1, n):
                fator = a[r][i] / a[i][i]
                for c in range(i, n):
                    a[r][c] -= fator * a[i][c]

        return det

    @staticmethod
    def _resolver_sistema_linear(a: List[List[float]], b: List[float]) -> List[float]:
        """Resolve A x = b usando Eliminação Gaussiana com Pivoteamento Parcial."""
        n = len(b)
        # Matriz aumentada [A | b]
        m_aum = [a[i][:] + [b[i]] for i in range(n)]

        for i in range(n):
            # Pivoteamento parcial
            max_row = i
            for r in range(i + 1, n):
                if abs(m_aum[r][i]) > abs(m_aum[max_row][i]):
                    max_row = r
            if abs(m_aum[max_row][i]) < 1e-12:
                raise ValueError("Sistema singular ou impossível de inverter com precisão numérica.")

            m_aum[i], m_aum[max_row] = m_aum[max_row], m_aum[i]

            # Eliminação para frente
            for r in range(i + 1, n):
                fator = m_aum[r][i] / m_aum[i][i]
                for c in range(i, n + 1):
                    m_aum[r][c] -= fator * m_aum[i][c]

        # Substituição regressiva
        x = [0.0] * n
        for i in range(n - 1, -1, -1):
            soma = sum(m_aum[i][j] * x[j] for j in range(i + 1, n))
            x[i] = (m_aum[i][n] - soma) / m_aum[i][i]

        return x

    # =========================================================================
    # MOTOR PRINCIPAL DO MODELO DE RISCO
    # =========================================================================
    def calcular_risco(
        self,
        severidades_cve: Optional[Dict[str, float]] = None,
        aplicar_polimorfismo: bool = True,
    ) -> ResultadoAnaliseRisco:
        """Executa a montagem de M, v, A e resolve o sistema linear (I - A) x = b."""
        ativos_dict = self.repositorio.listar_todos()
        if not ativos_dict:
            return ResultadoAnaliseRisco(
                sucesso=False,
                mensagem="Nenhum ativo/equipamento cadastrado para análise de risco.",
            )

        # Ordena equipamentos por ID para garantir ordem estável nas matrizes
        equipamentos: List[Ativo] = sorted(ativos_dict.values(), key=lambda eq: eq.id_ativo)
        n = len(equipamentos)
        mapa_id_indice = {eq.id_ativo: i for i, eq in enumerate(equipamentos)}

        # Coleta todas as vulnerabilidades únicas
        cves_set = set()
        for eq in equipamentos:
            for cve in eq.vulnerabilidades:
                cves_set.add(cve.strip().upper())

        cves_lista = sorted(list(cves_set))
        m = len(cves_lista)
        mapa_cve_indice = {cve: j for j, cve in enumerate(cves_lista)}

        # 1. Matriz de Incidência M (n x m)
        matriz_M = [[0] * m for _ in range(n)]
        for i, eq in enumerate(equipamentos):
            for cve in eq.vulnerabilidades:
                cve_up = cve.strip().upper()
                if cve_up in mapa_cve_indice:
                    j = mapa_cve_indice[cve_up]
                    matriz_M[i][j] = 1

        # 2. Vetor de Severidade v (m elementos)
        # Se não fornecido ou incompleto, usa notas CVSS típicas ou padrão (7.5)
        severidades = severidades_cve if severidades_cve else {}
        vetor_v: List[float] = []
        for cve in cves_lista:
            # Nota padrão de risco CVSS se não estiver cadastrada
            nota = float(severidades.get(cve, 7.5))
            vetor_v.append(nota)

        # 3. Risco Próprio b = M * v (ponderado por fator_exposicao polimórfico)
        vetor_b: List[float] = [0.0] * n
        for i, eq in enumerate(equipamentos):
            soma_risco_cves = sum(matriz_M[i][j] * vetor_v[j] for j in range(m))
            if aplicar_polimorfismo and hasattr(eq, "fator_exposicao"):
                fator = eq.fator_exposicao()
            else:
                fator = 1.0
            vetor_b[i] = soma_risco_cves * fator

        # 4. Matriz de Dependências A (n x n)
        matriz_A = [[0.0] * n for _ in range(n)]
        for i, eq in enumerate(equipamentos):
            deps = eq.obter_dependencias()
            for id_alvo, peso in deps.items():
                if id_alvo in mapa_id_indice:
                    j = mapa_id_indice[id_alvo]
                    matriz_A[i][j] = float(peso)

        # 5. Matriz (I - A)
        matriz_I_A = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                delta_ij = 1.0 if i == j else 0.0
                matriz_I_A[i][j] = delta_ij - matriz_A[i][j]

        # 6. Verificação de Invertibilidade e Número de Condição
        if TEM_NUMPY:
            np_I_A = np.array(matriz_I_A, dtype=float)
            np_b = np.array(vetor_b, dtype=float)

            det = float(np.linalg.det(np_I_A))
            try:
                cond = float(np.linalg.cond(np_I_A))
            except Exception:
                cond = float("inf")

            invertivel = abs(det) > 1e-9 and cond < 1e12

            if not invertivel:
                return ResultadoAnaliseRisco(
                    sucesso=False,
                    mensagem=(
                        f"A matriz (I - A) NÃO é invertível (det={det:.6e}, cond={cond:.2e}). "
                        "Revise as frações de dependência para eliminar ciclos singulares."
                    ),
                    equipamentos_ids=[eq.id_ativo for eq in equipamentos],
                    equipamentos_hostnames=[eq.hostname for eq in equipamentos],
                    matriz_A=matriz_A,
                    matriz_I_A=matriz_I_A,
                    determinante=det,
                    numero_condicao=cond,
                    invertivel=False,
                )

            # Resolução direta via NumPy (mais precisa e eficiente do que inversa)
            vetor_x_arr = np.linalg.solve(np_I_A, np_b)
            vetor_x = [float(val) for val in vetor_x_arr]

        else:
            # Fallback sem NumPy
            det = self._calcular_determinante(matriz_I_A)
            invertivel = abs(det) > 1e-9
            cond = 1.0  # Estimativa simplificada no fallback

            if not invertivel:
                return ResultadoAnaliseRisco(
                    sucesso=False,
                    mensagem=f"A matriz (I - A) é singular ou teoricamente nula (det={det:.6e}).",
                    equipamentos_ids=[eq.id_ativo for eq in equipamentos],
                    matriz_A=matriz_A,
                    matriz_I_A=matriz_I_A,
                    determinante=det,
                    invertivel=False,
                )

            try:
                vetor_x = self._resolver_sistema_linear(matriz_I_A, vetor_b)
            except ValueError as e:
                return ResultadoAnaliseRisco(
                    sucesso=False,
                    mensagem=f"Erro ao resolver o sistema linear: {e}",
                    determinante=det,
                    invertivel=False,
                )

        # 7. Montagem da Tabela Detalhada para Consulta na Aplicação
        tabela = []
        for i, eq in enumerate(equipamentos):
            fator = eq.fator_exposicao() if hasattr(eq, "fator_exposicao") else 1.0
            tabela.append({
                "id": eq.id_ativo,
                "hostname": eq.hostname,
                "tipo": eq.tipo,
                "fator_exposicao": round(fator, 2),
                "total_cves": len(eq.vulnerabilidades),
                "risco_proprio": round(vetor_b[i], 4),
                "risco_efetivo": round(vetor_x[i], 4),
                "dependencias": eq.obter_dependencias(),
            })

        return ResultadoAnaliseRisco(
            sucesso=True,
            mensagem="Análise de Risco por Álgebra Linear concluída com sucesso!",
            equipamentos_ids=[eq.id_ativo for eq in equipamentos],
            equipamentos_hostnames=[eq.hostname for eq in equipamentos],
            vulnerabilidades_cves=cves_lista,
            matriz_M=matriz_M,
            vetor_v=vetor_v,
            vetor_b=vetor_b,
            matriz_A=matriz_A,
            matriz_I_A=matriz_I_A,
            invertivel=True,
            determinante=det,
            numero_condicao=cond,
            vetor_x=vetor_x,
            tabela_detalhada=tabela,
        )


# Instância padrão para importação direta
_servico_risco_padrao = RiscoLinearService()


def calcular_risco_linear(
    severidades_cve: Optional[Dict[str, float]] = None,
    aplicar_polimorfismo: bool = True,
) -> ResultadoAnaliseRisco:
    return _servico_risco_padrao.calcular_risco(
        severidades_cve=severidades_cve,
        aplicar_polimorfismo=aplicar_polimorfismo,
    )
