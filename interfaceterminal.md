from enum import Enum

# ==========================================
# 1. ENUMERAÇÃO DE TIPOS DE ATIVOS (Requisito 2)
# ==========================================
class TipoAtivo(Enum):
    SERVIDORES = 1
    ROTEADORES_SWITCHES = 2
    COMPUTADORES = 3
    IMPRESSORAS = 4

# Base de dados em memória (Dicionário indexado por ID - Requisito 9)
base_ativos = {}

# ==========================================
# 2. FUNÇÕES AUXILIARES E VALIDAÇÕES
# ==========================================
def selecionar_tipo_ativo():
    """Exibe os tipos da Enum e valida a escolha do usuário."""
    print("\n--- Tipos de Ativos Disponíveis ---")
    for tipo in TipoAtivo:
        print(f"[{tipo.value}] {tipo.name.replace('_', ' ').title()}")
    
    while True:
        try:
            opcao = int(input("Escolha o código do tipo de ativo: "))
            if opcao in [tipo.value for tipo in TipoAtivo]:
                return TipoAtivo(opcao)
            else:
                print("⚠️ Código inválido! Escolha um número da lista acima.")
        except ValueError:
            print("⚠️ Entrada inválida! Digite apenas números inteiros.")

def exibir_dados_ativo(id_ativo, ativo):
    """Exibe as informações detalhadas de um ativo e suas vulnerabilidades."""
    print("\n----------------------------------")
    print(f"🆔 ID: {id_ativo}")
    print(f"💻 Hostname: {ativo['hostname']}")
    print(f"👤 Responsável: {ativo['responsavel']}")
    print(f"📍 Localização: {ativo['localizacao']}")
    print(f"🏷️ Tipo: {ativo['tipo']}")
    
    # Requisito 8: Trata exibição de vulnerabilidades
    if ativo['vulnerabilidades']:
        print(f"⚠️ Vulnerabilidades registradas ({len(ativo['vulnerabilidades'])}):")
        for vuln in ativo['vulnerabilidades']:
            print(f"  • Código/CVE: {vuln['cve']} | Severidade: {vuln['severidade']} | Status: {vuln['status']}")
    else:
        print("✅ Nenhuma vulnerabilidade registrada para este ativo.")
    print("----------------------------------")

# ==========================================
# 3. OPERAÇÕES DE CRUD E VULNERABILIDADES
# ==========================================
def cadastrar_ativo():
    """Cadastra um novo ativo na base de dados (Create - Requisito 3)."""
    print("\n--- ➕ Cadastrar Novo Ativo ---")
    try:
        id_ativo = int(input("Digite o ID único do ativo (número): "))
        if id_ativo in base_ativos:
            print("⚠️ Erro: Já existe um ativo cadastrado com este ID!")
            return

        hostname = input("Digite o nome/hostname do ativo: ").strip()
        while not hostname:
            print("⚠️ O hostname não pode ficar em branco!")
            hostname = input("Digite um hostname válido: ").strip()

        responsavel = input("Digite o nome do responsável: ").strip()
        localizacao = input("Digite o setor ou localização: ").strip()
        
        tipo = selecionar_tipo_ativo()

        # Salvando a estrutura completa no dicionário
        base_ativos[id_ativo] = {
            "hostname": hostname,
            "responsavel": responsavel,
            "localizacao": localizacao,
            "tipo": tipo.name,
            "vulnerabilidades": []
        }
        print(f"\n✅ Ativo '{hostname}' cadastrado com sucesso!")

    except ValueError:
        print("⚠️ Erro: O ID deve ser um número inteiro válido.")

def buscar_ativo():
    """Realiza a busca por ID ou por Hostname (Read - Requisito 4)."""
    print("\n--- 🔍 Consultar Ativo ---")
    print("[1] Buscar por ID")
    print("[2] Buscar por Hostname")
    
    opcao = input("Escolha a opção de busca: ").strip()
    
    if opcao == "1":
        try:
            id_ativo = int(input("Digite o ID do ativo: "))
            if id_ativo in base_ativos:
                exibir_dados_ativo(id_ativo, base_ativos[id_ativo])
            else:
                print("⚠️ Ativo não encontrado com esse ID.")
        except ValueError:
            print("⚠️ Erro: Digite um número inteiro válido.")
            
    elif opcao == "2":
        nome_busca = input("Digite o Hostname (ou parte dele): ").strip().lower()
        encontrados = False
        for id_ativo, ativo in base_ativos.items():
            if nome_busca in ativo['hostname'].lower():
                exibir_dados_ativo(id_ativo, ativo)
                encontrados = True
        if not encontrados:
            print("⚠️ Nenhum ativo encontrado com esse Hostname.")
    else:
        print("⚠️ Opção de busca inválida.")

def alterar_ativo():
    """Atualiza as informações do ativo (Update - Requisito 5)."""
    print("\n--- ✏️ Alterar Dados do Ativo ---")
    try:
        id_ativo = int(input("Digite o ID do ativo que deseja alterar: "))
        if id_ativo not in base_ativos:
            print("⚠️ Erro: Ativo não encontrado!")
            return

        ativo = base_ativos[id_ativo]
        print(f"Alterando ativo: {ativo['hostname']} (Pressione ENTER para manter o valor atual)\n")

        novo_hostname = input(f"Novo Hostname [{ativo['hostname']}]: ").strip()
        if novo_hostname:
            ativo['hostname'] = novo_hostname

        novo_responsavel = input(f"Novo Responsável [{ativo['responsavel']}]: ").strip()
        if novo_responsavel:
            ativo['responsavel'] = novo_responsavel

        nova_localizacao = input(f"Nova Localização [{ativo['localizacao']}]: ").strip()
        if nova_localizacao:
            ativo['localizacao'] = nova_localizacao

        mudar_tipo = input("Deseja alterar o Tipo do Ativo? (s/N): ").strip().lower()
        if mudar_tipo == 's':
            novo_tipo = selecionar_tipo_ativo()
            ativo['tipo'] = novo_tipo.name

        print(f"\n✅ Ativo ID {id_ativo} atualizado com sucesso!")

    except ValueError:
        print("⚠️ Erro: Digite um ID numérico válido.")

def excluir_ativo():
    """Remove um ativo da base de dados (Delete - Requisito 6)."""
    print("\n--- 🗑️ Excluir Ativo ---")
    try:
        id_ativo = int(input("Digite o ID do ativo que deseja excluir: "))
        if id_ativo in base_ativos:
            ativo_removido = base_ativos.pop(id_ativo)
            print(f"✅ Ativo '{ativo_removido['hostname']}' excluído com sucesso!")
        else:
            print("⚠️ Erro: Ativo não encontrado na base de dados.")
    except ValueError:
        print("⚠️ Erro: Digite um número inteiro válido.")

def gerenciar_vulnerabilidades():
    """Registra novos códigos de falha, severidade e status em um ativo (Requisito 7)."""
    print("\n--- ⚠️ Gerenciar Vulnerabilidades / Riscos ---")
    try:
        id_ativo = int(input("Digite o ID do ativo afetado: "))
        if id_ativo not in base_ativos:
            print("⚠️ Ativo não encontrado!")
            return

        cve = input("Digite o código/CVE da vulnerabilidade: ").strip()
        severidade = input("Digite a severidade (Baixa/Média/Alta/Crítica): ").strip()
        status = input("Digite o status (Identificada/Em Correção/Mitigada): ").strip()

        nova_vuln = {
            "cve": cve,
            "severidade": severidade,
            "status": status
        }

        base_ativos[id_ativo]["vulnerabilidades"].append(nova_vuln)
        print(f"\n✅ Vulnerabilidade '{cve}' associada ao ativo ID {id_ativo} com sucesso!")

    except ValueError:
        print("⚠️ Erro: Digite um ID numérico válido.")

# ==========================================
# 4. MENU PRINCIPAL (LAÇO INTERATIVO)
# ==========================================
def main():
    while True:
        print("\n" + "="*40)
        print("🔒 SISTEMA DE INVENTÁRIO DE TI E SEGURANÇA")
        print("="*40)
        print("[1] Cadastrar novo ativo")
        print("[2] Consultar ativo (por ID ou Hostname)")
        print("[3] Alterar dados de um ativo")
        print("[4] Excluir ativo")
        print("[5] Cadastrar vulnerabilidade / risco")
        print("[0] Sair do sistema")
        print("="*40)
        
        try:
            opcao = int(input("Escolha uma opção: "))
            
            if opcao == 1:
                cadastrar_ativo()
            elif opcao == 2:
                buscar_ativo()
            elif opcao == 3:
                alterar_ativo()
            elif opcao == 4:
                excluir_ativo()
            elif opcao == 5:
                gerenciar_vulnerabilidades()
            elif opcao == 0:
                print("\nEncerrando o sistema... Até logo! 👋")
                break
            else:
                print("⚠️ Opção inválida! Escolha um número do menu.")
                
        except ValueError:
            print("⚠️ Entrada inválida! Por favor, digite apenas números inteiros.")

if __name__ == "__main__":
    main()
