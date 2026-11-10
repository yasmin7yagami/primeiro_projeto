# 🛡️ Trabalho 02 — Gestão de Inventário de TI e Análise de Vulnerabilidades

**Aluna:** Yasmin Araujo Miranda  
**Disciplina / Curso:** Cibersegurança & Desenvolvimento de Software — UFU  
**Sprints:** 3, 4 e 5  

---

## 📌 Visão Geral do Projeto

Sistema em Python com interface gráfica moderna (**CustomTkinter**) e suporte a containers (**Docker**) voltado para o inventário de ativos de rede (Servidores, Switches/Roteadores, Computadores e Impressoras) e integração direta com a base oficial de dados do **NIST/NVD** para verificação, tradução automática e vinculação de vulnerabilidades (**CVEs**).

---

## 🏛️ Arquitetura em Camadas (Requisito `[S4_01]`)

O projeto foi desacoplado em camadas com responsabilidades bem definidas, eliminando dependências circulares e separando a lógica de negócio da tecnologia de interface e persistência:

```
primeiro_projeto/
├── config.py                 # Configurações globais, cores, temas e caminhos absolutos
├── models.py                 # Domínio e POO: Ativo, Servidor, Computador, Factory
├── utils.py                  # Funções auxiliares desacopladas (Regex, sanitização, tradução)
│
├── repositories/             # Camada de Persistência (Padrão Repository & DIP)
│   ├── base_repository.py    # Interface abstrata IAtivoRepository
│   ├── json_repository.py    # Persistência em JSON com gravação atômica
│   └── memory_repository.py  # Persistência em memória (para testes unitários)
│
├── strategies/               # Padrão Strategy (Critérios de Ordenação e Risco)
│   └── ordenacao_strategy.py # Ordenação por ID, Hostname e Criticidade
│
├── services/                 # Camada de Regras de Negócio e Serviços
│   ├── auth_service.py       # Autenticação segura com Hashing PBKDF2 e Salt
│   ├── asset_service.py      # Gestão de ativos com injeção de repositório
│   └── cve_service.py        # Integração HTTP com a API da NVD/NIST e Cache
│
├── ui/                       # Camada de Apresentação (Interface CustomTkinter)
│   ├── login_window.py       # Janela de Login e controle de sessão
│   ├── main_window.py        # Aplicação principal e coordenação de abas
│   └── tabs/                 # Componentes individuais de abas
│
├── tests/                    # Suíte de Testes Automatizados com Pytest
│   ├── conftest.py           # Fixtures (memória e tmp_path)
│   ├── test_models.py        # Testes de POO e Factory
│   ├── test_repository.py    # Testes de persistência JSON e atômica
│   ├── test_service.py       # Testes de validação e regras de negócio
│   └── test_strategies.py    # Testes de ordenação e padrão Strategy
│
├── Dockerfile                # Imagem Docker multi-camada com usuário não-root
├── compose.yaml              # Orquestração com política de reinício e volumes
└── interfacegrafica.py       # Ponto de entrada da aplicação
```

---

## 🧩 Princípios SOLID e Padrões de Projeto Aplicados (`[S4_02]` e `[S4_03]`)

### 1. SOLID
- **SRP (Single Responsibility Principle):** Cada módulo possui uma única razão para mudar. A camada de serviços (`AssetService`) não desenha widgets, e a camada de interface não grava arquivos em disco.
- **OCP (Open/Closed Principle):** Novos tipos de ativos podem ser adicionados criando novas subclasses derivadas de `Ativo` e registrando no `AtivoFactory`, sem modificar a lógica dos serviços existentes.
- **LSP (Liskov Substitution Principle):** Qualquer subclasse (`Servidor`, `Computador`, `RoteadorSwitch`, `Impressora`) substitui a classe base `Ativo` mantendo o comportamento esperado em coleções heterogêneas.
- **ISP (Interface Segregation Principle):** A interface `IAtivoRepository` define apenas os métodos essenciais de persistência.
- **DIP (Dependency Inversion Principle):** `AssetService` depende da abstração `IAtivoRepository`, e não de implementações concretas de arquivos ou bancos de dados.

### 2. Padrões de Projeto (Design Patterns)
- **Factory Method (`AtivoFactory`):** Centraliza a criação das subclasses polimórficas a partir do campo `"tipo"` e a desserialização de JSON.
- **Repository Pattern (`IAtivoRepository`):** Isola completamente o acesso a dados. Permite alternar entre `JsonAtivoRepository` e `MemoriaAtivoRepository` sem alterar uma única linha da camada de serviço.
- **Strategy Pattern (`IOrdenacaoStrategy`):** Permite alternar algoritmos de ordenação em tempo de execução (por ID numérico, alfabético por hostname ou por nível de criticidade de vulnerabilidades), além de suporte funcional via funções de primeira classe.

---

## 💾 Persistência com Escrita Atômica (`[S4_04]`)

Para evitar corrupção de dados em caso de interrupção inesperada ou queda de energia durante a gravação, a persistência no `JsonAtivoRepository`:
1. Escreve os dados em um arquivo temporário (`base_ativos.json.tmp`).
2. Garante a codificação UTF-8 com `ensure_ascii=False`.
3. Executa a substituição atômica no sistema operacional via `os.replace()`.

---

## 🧪 Testes Automatizados com Pytest (`[S4_14]`)

A suíte de testes cobre a camada de domínio, repositórios, serviços e estratégias com fixtures e testes parametrizados:

```bash
# Executar todos os testes
pytest tests/

# Executar testes com relatório detalhado e medição de cobertura
pytest --cov=. --cov-report=term-missing tests/
```

---

## 🐳 Containerização com Docker e Docker Compose (`[S4_16]`, `[S4_17]`, `[S5_20]`)

O projeto inclui containerização pronta para produção, atendendo a todos os requisitos de segurança:
- Imagem enxuta baseada em `python:3.11-slim`.
- Execução como usuário sem privilégios (`appuser`).
- Persistência com volume Docker e política `restart: unless-stopped` para manter o serviço em execução contínua por 24 horas.

### Comandos Docker:
```bash
# Construir a imagem localmente
docker build -t trab02_app .

# Inicializar o container com persistência via Docker Compose
docker compose up -d

# Visualizar logs da aplicação em execução
docker compose logs -f
```

---

## 🚀 Como Executar a Aplicação Localmente

```bash
# 1. Instalar as dependências
pip install -r requirements.txt

# 2. Executar a interface gráfica
python interfacegrafica.py
```

*Credenciais de Administrador padrão:*
- **Usuário:** `admin`
- **Senha:** `admin123`
