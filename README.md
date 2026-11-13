# 🛡️ Trabalho 02 — Aplicação de Inventário em Orientação a Objetos e Análise de Risco

**Aluna:** Yasmin Araujo Miranda  
**Curso / Disciplina:** Bacharelado em Cibersegurança — Universidade Federal de Uberlândia (UFU)  
**Ciclo de Aprendizagem:** Sprints 3, 4 e 5  
**Data Limite de Entrega:** 27/11/2026  

---

## 📌 Atendimento aos Requisitos Oficiais (Tabela 1 do Edital)

| Nº | Requisito Oficial | Peso | Status | Implementação |
| :-: | :--- | :-: | :-: | :--- |
| **1** | Cada ativo deve ser representado por um objeto individual (`classe equipamentos`), com subclasses derivadas. | **20%** | Concluído | Classes em `models.py`: `Equipamento` (superclasse abstrata) com subclasses `Servidor`, `RoteadorSwitch`, `Computador` e `Impressora`, métodos polimórficos (`exibir_detalhes`, `fator_exposicao`) e encapsulamento. |
| **2** | Cada ativo deve ser armazenado em arquivo formato JSON constituído por um **array (lista) de objetos JSON**. | **20%** | Concluído | `repositories/json_repository.py` serializa e persiste em disco como lista JSON `[ {...}, {...} ]`. Dependências entre ativos são salvas no mesmo arquivo. |
| **3** | A aplicação deve ser executada em um container e permanecer em funcionamento por, no mínimo, **24 horas**. | **45%** | Concluído | `Dockerfile` e `compose.yaml` com imagem leve `python:3.11-slim`, usuário não-root, `app_server.py` daemon com monitor contínuo, healthcheck a cada 30s e dashboard web na porta 8000. |
| **4** | Cálculo do risco efetivo por meio do **modelo linear** ($x = b + Ax \iff (I - A)x = b$), com verificação prévia de invertibilidade. | **15%** | Concluído | `services/risco_service.py` calcula $M$, $v$, $b$, $A$, valida invertibilidade e número de condição de $(I - A)$, e resolve o sistema linear diretamente. Consulta visual no dashboard web e no sistema. |

---

## 📐 Modelo de Análise de Risco por Álgebra Linear (Requisito 4)

O modelo implementado segue rigorosamente as equações do edital:
1. **Matriz de Incidência $M \in \{0, 1\}^{n \times m}$:** $M_{ij} = 1$ se o equipamento $i$ é afetado pela vulnerabilidade $j$.
2. **Vetor de Severidade $v \in \mathbb{R}^m$:** Severidade de cada vulnerabilidade (nota CVSS v3).
3. **Risco Próprio $b = M \cdot v$:** Ponderado pelo método polimórfico `fator_exposicao()` de cada tipo de equipamento (`Servidor = 1.25`, `RoteadorSwitch = 1.10`, `Computador = 0.85`, `Impressora = 0.50`).
4. **Matriz de Dependências $A \in \mathbb{R}^{n \times n}$:** Fração do risco do equipamento $j$ transmitida ao equipamento $i$, com $A_{ii} = 0$, $A_{ij} \in [0, 1)$ e $\sum_j A_{ij} < 1$ (garante dominância diagonal estrita).
5. **Risco Efetivo $x \in \mathbb{R}^n$:**
   $$x = b + Ax \iff (I - A)x = b$$
6. **Invertibilidade:** O sistema verifica $\det(I - A) \neq 0$ e o número de condição $\text{cond}(I - A)$ antes da resolução direta por eliminação gaussiana/NumPy.

### 🧪 Cenário Resolvido à Mão (Testado e Validado)
Conforme exigido na Seção 2 do edital, o modelo foi validado com o seguinte cenário de 3 equipamentos:
* **E1 (ID 101):** Servidor Web (fator 1.25), com `CVE-2021-44228` (CVSS 10.0) $\implies b_1 = 1.25 \times 10.0 = 12.5$
* **E2 (ID 102):** Servidor Banco de Dados (fator 1.25), com `CVE-2022-22965` (CVSS 8.0) $\implies b_2 = 1.25 \times 8.0 = 10.0$
* **E3 (ID 103):** Roteador de Borda (fator 1.10), sem vulnerabilidades $\implies b_3 = 0.0$
* **Dependências:** E1 depende de E2 ($A_{12} = 0.30$); E3 depende de E1 ($A_{31} = 0.20$).

$$I - A = \begin{pmatrix} 1 & -0.30 & 0 \\ 0 & 1 & 0 \\ -0.20 & 0 & 1 \end{pmatrix}, \quad b = \begin{pmatrix} 12.5 \\ 10.0 \\ 0.0 \end{pmatrix}$$
* $\det(I - A) = 1.0 \neq 0$ (Invertível!).
* **Solução:**
  * $x_2 = 10.0$
  * $x_1 = 12.5 + 0.30(10.0) = \mathbf{15.5}$
  * $x_3 = 0.20(15.5) = \mathbf{3.1}$
  * Vetor de Risco Efetivo: $x = [15.5, 10.0, 3.1]^T$ (cobertura em `tests/test_analise_risco.py`).

---

## 🚀 Como Executar

### 1. Execução no Container Docker (Ambiente 24 Horas)
Para rodar a aplicação em background com reinício automático e monitoramento contínuo:
```bash
docker compose up -d --build
```
Acesse o Dashboard Web e as APIs em:
* **Dashboard Web:** `http://localhost:8000/`
* **Healthcheck:** `http://localhost:8000/api/health`
* **API de Risco (JSON):** `http://localhost:8000/api/risco`
* **API de Ativos (JSON):** `http://localhost:8000/api/ativos`

Para acompanhar os logs de auditoria contínua em tempo real:
```bash
docker logs -f trab02_inventario_app
```

### 2. Execução dos Testes Automatizados (Pytest)
```bash
pytest tests/ -v
```

### 3. Execução em Modo Gráfico Local (Windows Desktop)
```bash
python interfacegrafica.py
```

---

## 🏛️ Estrutura Arquitetural do Repositório

```text
primeiro_projeto/
├── app_server.py             # [Requisito 3] Servidor HTTP e Monitor Daemon 24h
├── config.py                 # Configurações globais e caminhos de arquivos
├── models.py                 # [Requisito 1] Classes POO: Equipamento, Servidor, Roteador, etc.
├── utils.py                  # Sanitização e validações
├── base_ativos.json          # [Requisito 2] Persistência em Array de Objetos JSON
├── usuarios.json             # Autenticação segura com hash PBKDF2
│
├── repositories/             # [Requisito 2] Padrão Repository
│   ├── base_repository.py    # Interface abstrata IAtivoRepository
│   ├── json_repository.py    # Persistência atômica em Array JSON
│   └── memory_repository.py  # Repositório em memória para testes
│
├── services/                 # Regras de Negócio
│   ├── risco_service.py      # [Requisito 4] Álgebra Linear: M, v, b, A, (I-A)x=b
│   ├── asset_service.py      # Gestão de inventário e validações
│   ├── auth_service.py       # Gestão de usuários e senhas
│   └── cve_service.py        # Integração com API da NVD/NIST
│
├── ui/                       # Interface Gráfica CustomTkinter
│   ├── login_window.py       # Tela de autenticação
│   ├── main_window.py        # Janela principal
│   └── tabs/                 # Abas (Novo Ativo, Atualizar, CVE, Relatório & Risco)
│
├── tests/                    # Suíte de Testes Automatizados (Pytest)
│   ├── conftest.py           # Fixtures de teste
│   ├── test_models.py        # Testes de POO e Herança
│   ├── test_repository.py    # Testes de persistência em lista JSON
│   ├── test_analise_risco.py # [Requisito 4] Validação do modelo linear e invertibilidade
│   └── test_service.py       # Testes de serviços
│
├── Dockerfile                # [Requisito 3] Imagem Docker com usuário não-root e healthcheck
├── compose.yaml              # [Requisito 3] Orquestração para operação contínua 24h
└── requirements.txt          # Dependências congeladas (numpy, requests, pytest)
```
