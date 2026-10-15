# ==========================================
# PERSISTÊNCIA DE DADOS DOS ATIVOS 💾
# ==========================================
def salvar_dados_ativos():
    try:
        dados = {str(k): v for k, v in base_ativos.items()}
        with open(NOME_ARQUIVO_ATIVOS, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar ativos: {e}")
        return False


def carregar_dados_ativos():
    global base_ativos
    try:
        with open(NOME_ARQUIVO_ATIVOS, "r", encoding="utf-8") as f:
            base_ativos = {int(k): v for k, v in json.load(f).items()}
    except (FileNotFoundError, json.JSONDecodeError):
        base_ativos = {}


def carregar_usuarios():
    try:
        with open(NOME_ARQUIVO_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)
            if (
                "admin" in usuarios
                and usuarios["admin"].get("role") != "admin"
            ):
                usuarios["admin"]["role"] = "admin"
                with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f_out:
                    json.dump(usuarios, f_out, indent=4, ensure_ascii=False)
            return usuarios
    except (FileNotFoundError, json.JSONDecodeError):
        usuarios_iniciais = {
            "admin": {
                "hash": gerar_hash_senha("admin123"),
                "nome": "Administrador UFU",
                "role": "admin",
            }
        }
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios_iniciais, f, indent=4, ensure_ascii=False)
        return usuarios_iniciais


def salvar_usuario(usuario, senha, nome, role="user"):
    usuarios = carregar_usuarios()
    usuarios[usuario] = {
        "hash": gerar_hash_senha(senha),
        "nome": nome,
        "role": role,
    }
    with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=4, ensure_ascii=False)


def atualizar_role_usuario(usuario, novo_role):
    usuarios = carregar_usuarios()
    if usuario in usuarios:
        usuarios[usuario]["role"] = novo_role
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
        return True
    return False


def deletar_usuario(usuario):
    if usuario.lower() == "admin":
        return False, "O usuário 'admin' padrão não pode ser removido!"

    usuarios = carregar_usuarios()
    if usuario in usuarios:
        del usuarios[usuario]
        with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
        return True, f"Usuário '{usuario}' removido com sucesso!"
    return False, "Usuário não encontrado."

# ==========================================
# 💾 PERSISTÊNCIA E CACHE DE CVES LOCAL
# ==========================================
def carregar_cves_locais():
    if not os.path.exists(NOME_ARQUIVO_CVES):
        return {}
    try:
        with open(NOME_ARQUIVO_CVES, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def guardar_cve_local(codigo_cve, dados_cve):
    dados_locais = carregar_cves_locais()
    dados_locais[codigo_cve] = dados_cve
    try:
        with open(NOME_ARQUIVO_CVES, "w", encoding="utf-8") as f:
            json.dump(dados_locais, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar cache da CVE: {e}")
        return False