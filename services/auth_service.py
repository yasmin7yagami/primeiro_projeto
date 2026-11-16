import hashlib
import json
import secrets
from config import NOME_ARQUIVO_USUARIOS

def gerar_hash_senha(senha, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt.encode("utf-8"), 100000
    )
    return f"{salt}${key.hex()}"

def verificar_senha(senha_digitada, hash_salvo):
    try:
        salt, key_hex = hash_salvo.split("$")
        novo_hash = hashlib.pbkdf2_hmac(
            "sha256", senha_digitada.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()
        return secrets.compare_digest(novo_hash, key_hex)
    except Exception:
        return False

def carregar_usuarios():
    try:
        with open(NOME_ARQUIVO_USUARIOS, "r", encoding="utf-8-sig") as f:
            usuarios = json.load(f)
            if "admin" in usuarios and usuarios["admin"].get("role") != "admin":
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

def alterar_senha_usuario(login_id, senha_atual, nova_senha):
    if len(nova_senha) < 6:
        return False, "A nova senha deve ter pelo menos 6 caracteres."

    usuarios = carregar_usuarios()
    if login_id not in usuarios:
        return False, "Usuário não encontrado!"

    if not verificar_senha(senha_atual, usuarios[login_id]["hash"]):
        return False, "Senha atual incorreta!"

    usuarios[login_id]["hash"] = gerar_hash_senha(nova_senha)
    with open(NOME_ARQUIVO_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=4, ensure_ascii=False)

    return True, "Senha alterada com sucesso!"

def autenticar_usuario(usuario, senha):
    usuarios = carregar_usuarios()
    if usuario in usuarios and verificar_senha(senha, usuarios[usuario]["hash"]):
        dados = usuarios[usuario]
        return True, {
            "nome": dados.get("nome", usuario),
            "role": dados.get("role", "user"),
            "login_id": usuario,
        }
    return False, "Usuário ou senha incorretos!"
