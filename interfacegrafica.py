import json
import os
import sys
import io
import re
from enum import Enum
import customtkinter as ctk

# Configuração para terminal do Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Configuração do Tema 🌙
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class TipoAtivo(Enum):
    SERVIDORES = "Servidores"
    ROTEADORES_SWITCHES = "Roteadores/Switches"
    COMPUTADORES = "Computadores"
    IMPRESSORAS = "Impressoras"

base_ativos = {}
NOME_ARQUIVO = "base_ativos.json"

# ==========================================
# 🛡️ MÓDULO DE VERIFICAÇÃO DE SEGURANÇA
# ==========================================
def sanitizar_texto(texto):
    """Remove caracteres perigosos ou desnecessários para prevenir injeções."""
    if not texto:
        return ""
    # Remove tags HTML e caracteres especiais de controle
    texto_limpo = re.sub(r'[<>\'\"\\;]', '', texto)
    return texto_limpo.strip()

def validar_cve(cve_texto):
    """Valida estritamente se o código segue o padrão CVE-YYYY-NNNN (ou mais dígitos)."""
    cve_limpo = cve_texto.strip().upper()
    padrao_cve = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(padrao_cve, cve_limpo))

def validar_hostname(hostname):
    """Garante que o hostname contenha apenas letras, números, hífen e ponto."""
    if not hostname or len(hostname) > 63:
        return False
    padrao_hostname = r'^[a-zA-Z0-9.-]+$'
    return bool(re.match(padrao_hostname, hostname))

def validar_id(id_str):
    """Garante que o ID seja um número inteiro positivo válido."""
    if not id_str.isdigit():
        return False, "O ID deve conter apenas números inteiros!"
    val = int(id_str)
    if val <= 0 or val > 999999:
        return False, "O ID deve ser um número entre 1 e 999999!"
    return True, val

# ==========================================
# PERSISTÊNCIA DE DADOS 💾
# ==========================================
def salvar_dados():
    try:
        dados_para_salvar = {str(k): v for k, v in base_ativos.items()}
        with open(NOME_ARQUIVO, "w", encoding="utf-8") as arquivo:
            json.dump(dados_para_salvar, arquivo, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Erro ao salvar: {e}")
        return False

def carregar_dados():
    global base_ativos
    try:
        with open(NOME_ARQUIVO, "r", encoding="utf-8") as arquivo:
            dados_carregados = json.load(arquivo)
            base_ativos = {int(k): v for k, v in dados_carregados.items()}
    except (FileNotFoundError, json.JSONDecodeError):
        base_ativos = {}

# ==========================================
# INTERFACE GRÁFICA AJUSTADA 🖥️
# ==========================================
class AplicacaoInventario(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de Gestão de Ativos & Cibersegurança 🔒")
        self.geometry("720x740")
        self.resizable(False, False)

        carregar_dados()

        # Cabeçalho
        self.header_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1f2937")
        self.header_frame.pack(pady=10, padx=15, fill="x")

        self.titulo = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ CYBERASSET MANAGER (SECURE)", 
            font=("Segoe UI", 20, "bold"),
            text_color="#60a5fa"
        )
        self.titulo.pack(pady=12)

        # Sistema de Abas
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(pady=5, padx=15, fill="both", expand=True)

        self.tab_ativos = self.tabview.add("💻 Gestão de Ativos")
        self.tab_cve = self.tabview.add("⚠️ Vulnerabilidades")
        self.tab_relatorio = self.tabview.add("📊 Relatório Geral")

        # Configuração das Abas
        self.setup_aba_ativos()
        self.setup_aba_cve()
        self.setup_aba_relatorio()

        # Barra de Status na base da janela
        self.lbl_status = ctk.CTkLabel(self, text="🔒 Validação de Segurança Ativa.", font=("Segoe UI", 11, "bold"), text_color="#9ca3af")
        self.lbl_status.pack(pady=8)

        self.func_atualizar_relatorio()

    # ----------------------------------------------------
    # LAYOUT DAS ABAS
    # ----------------------------------------------------
    def setup_aba_ativos(self):
        frame_cad = ctk.CTkFrame(self.tab_ativos, corner_radius=8)
        frame_cad.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(frame_cad, text="Cadastrar / Atualizar Ativo", font=("Segoe UI", 13, "bold")).pack(pady=8)

        self.entry_id = ctk.CTkEntry(frame_cad, placeholder_text="ID do Ativo (ex: 101)", width=320)
        self.entry_id.pack(pady=5)

        self.entry_hostname = ctk.CTkEntry(frame_cad, placeholder_text="Hostname (ex: srv-db-01)", width=320)
        self.entry_hostname.pack(pady=5)

        self.entry_responsavel = ctk.CTkEntry(frame_cad, placeholder_text="Responsável (ex: Ana Silva)", width=320)
        self.entry_responsavel.pack(pady=5)

        self.entry_localizacao = ctk.CTkEntry(frame_cad, placeholder_text="Localização (ex: Data Center)", width=320)
        self.entry_localizacao.pack(pady=5)

        self.combo_tipo = ctk.CTkComboBox(frame_cad, values=[t.value for t in TipoAtivo], width=320)
        self.combo_tipo.pack(pady=5)

        self.btn_salvar = ctk.CTkButton(frame_cad, text="Salvar Ativo 💾", fg_color="#2563eb", hover_color="#1d4ed8", command=self.func_cadastrar_ativo)
        self.btn_salvar.pack(pady=12)

        # Frame de Remoção
        frame_del = ctk.CTkFrame(self.tab_ativos, corner_radius=8)
        frame_del.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(frame_del, text="Excluir Ativo da Base", font=("Segoe UI", 13, "bold"), text_color="#f87171").pack(pady=6)

        sub_frame = ctk.CTkFrame(frame_del, fg_color="transparent")
        sub_frame.pack(pady=5)

        self.entry_del_id = ctk.CTkEntry(sub_frame, placeholder_text="ID p/ remover", width=160)
        self.entry_del_id.pack(side="left", padx=5)

        self.btn_deletar = ctk.CTkButton(sub_frame, text="Remover 🗑️", fg_color="#dc2626", hover_color="#991b1b", width=120, command=self.func_deletar_ativo)
        self.btn_deletar.pack(side="left", padx=5)

    def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(self.tab_cve, corner_radius=8)
        frame_cve.pack(pady=15, padx=20, fill="x")

        ctk.CTkLabel(frame_cve, text="Vincular Vulnerabilidade (CVE)", font=("Segoe UI", 14, "bold")).pack(pady=10)

        self.entry_cve_id = ctk.CTkEntry(frame_cve, placeholder_text="ID do Ativo Alvo (ex: 101)", width=320)
        self.entry_cve_id.pack(pady=6)

        self.entry_cve_cod = ctk.CTkEntry(frame_cve, placeholder_text="Código CVE (ex: CVE-2026-1042)", width=320)
        self.entry_cve_cod.pack(pady=6)

        # Seleção de Severidade
        ctk.CTkLabel(frame_cve, text="Severidade da Vulnerabilidade:", font=("Segoe UI", 11, "bold")).pack(pady=(6, 2))
        self.combo_severidade = ctk.CTkComboBox(frame_cve, values=["Baixa", "Média", "Alta", "Crítica"], width=320)
        self.combo_severidade.set("Alta")
        self.combo_severidade.pack(pady=4)

        # Seleção de Status
        ctk.CTkLabel(frame_cve, text="Status da Vulnerabilidade:", font=("Segoe UI", 11, "bold")).pack(pady=(6, 2))
        self.combo_status_cve = ctk.CTkComboBox(frame_cve, values=["Identificada", "Em Análise", "Em Correção", "Mitigada", "Corrigida"], width=320)
        self.combo_status_cve.set("Identificada")
        self.combo_status_cve.pack(pady=4)

        self.btn_add_cve = ctk.CTkButton(frame_cve, text="Vincular CVE 🔗", fg_color="#d97706", hover_color="#b45309", width=200, command=self.func_adicionar_cve)
        self.btn_add_cve.pack(pady=15)

    def setup_aba_relatorio(self):
        self.frame_cards = ctk.CTkFrame(self.tab_relatorio, fg_color="transparent")
        self.frame_cards.pack(pady=5, fill="x")

        self.card_ativos = ctk.CTkLabel(self.frame_cards, text="Ativos: 0", font=("Segoe UI", 12, "bold"), fg_color="#374151", corner_radius=6, width=150, height=30)
        self.card_ativos.pack(side="left", padx=10, expand=True)

        self.card_cves = ctk.CTkLabel(self.frame_cards, text="CVEs: 0", font=("Segoe UI", 12, "bold"), fg_color="#374151", corner_radius=6, width=150, height=30)
        self.card_cves.pack(side="right", padx=10, expand=True)

        self.caixa_relatorio = ctk.CTkTextbox(self.tab_relatorio, font=("Consolas", 12))
        self.caixa_relatorio.pack(pady=10, padx=5, fill="both", expand=True)
        self.caixa_relatorio.configure(state="disabled")

    # ----------------------------------------------------
    # REGRAS DE NEGÓCIO COM SEGURANÇA 🔒
    # ----------------------------------------------------
    def func_cadastrar_ativo(self):
        valido, res_id = validar_id(self.entry_id.get().strip())
        if not valido:
            self.lbl_status.configure(text=f"🛡️ Erro de Segurança: {res_id}", text_color="#f87171")
            return
        id_val = res_id

        hostname_bruto = self.entry_hostname.get()
        if not validar_hostname(hostname_bruto):
            self.lbl_status.configure(text="🛡️ Erro: Hostname inválido! Use apenas letras, números, '-' ou '.'", text_color="#f87171")
            return

        hostname = sanitizar_texto(hostname_bruto)
        responsavel = sanitizar_texto(self.entry_responsavel.get())
        localizacao = sanitizar_texto(self.entry_localizacao.get())

        vulnerabilidades_existentes = []
        if id_val in base_ativos:
            vulnerabilidades_existentes = base_ativos[id_val].get("vulnerabilidades", [])

        base_ativos[id_val] = {
            "hostname": hostname,
            "responsavel": responsavel,
            "localizacao": localizacao,
            "tipo": self.combo_tipo.get(),
            "vulnerabilidades": vulnerabilidades_existentes
        }

        salvar_dados()
        self.lbl_status.configure(text=f"✅ Ativo {id_val} validado e salvo com sucesso!", text_color="#4ade80")
        self.func_atualizar_relatorio()
        
        self.entry_id.delete(0, 'end')
        self.entry_hostname.delete(0, 'end')
        self.entry_responsavel.delete(0, 'end')
        self.entry_localizacao.delete(0, 'end')

    def func_adicionar_cve(self):
        valido, res_id = validar_id(self.entry_cve_id.get().strip())
        if not valido:
            self.lbl_status.configure(text=f"🛡️ Erro de Segurança: {res_id}", text_color="#f87171")
            return
        id_val = res_id

        if id_val not in base_ativos:
            self.lbl_status.configure(text="⚠️ Ativo não encontrado na base!", text_color="#facc15")
            return

        cve_cod = self.entry_cve_cod.get().strip().upper()
        if not validar_cve(cve_cod):
            self.lbl_status.configure(text="🛡️ Erro: CVE fora do padrão! Exemplo correto: CVE-2026-1042", text_color="#f87171")
            return

        severidade_val = self.combo_severidade.get()
        status_val = self.combo_status_cve.get()

        base_ativos[id_val]["vulnerabilidades"].append({
            "cve": cve_cod,
            "severidade": severidade_val,
            "status": status_val
        })

        salvar_dados()
        self.lbl_status.configure(text=f"✅ CVE '{cve_cod}' validada e associada ao Ativo {id_val}!", text_color="#4ade80")
        self.func_atualizar_relatorio()
        
        self.entry_cve_id.delete(0, 'end')
        self.entry_cve_cod.delete(0, 'end')

    def func_deletar_ativo(self):
        valido, res_id = validar_id(self.entry_del_id.get().strip())
        if not valido:
            self.lbl_status.configure(text=f"🛡️ Erro de Segurança: {res_id}", text_color="#f87171")
            return
        id_val = res_id

        if id_val in base_ativos:
            del base_ativos[id_val]
            salvar_dados()
            self.lbl_status.configure(text=f"🗑️ Ativo {id_val} removido com sucesso!", text_color="#4ade80")
            self.func_atualizar_relatorio()
            self.entry_del_id.delete(0, 'end')
        else:
            self.lbl_status.configure(text="⚠️ Ativo não encontrado!", text_color="#facc15")

    def func_atualizar_relatorio(self):
        self.caixa_relatorio.configure(state="normal")
        self.caixa_relatorio.delete("1.0", ctk.END)

        total_cves = 0
        if not base_ativos:
            self.caixa_relatorio.insert(ctk.END, "⚠️ Nenhum ativo cadastrado na base de dados.\n")
        else:
            for id_ativo, ativo in base_ativos.items():
                qtd_v = len(ativo.get('vulnerabilidades', []))
                total_cves += qtd_v

                texto = f"🆔 ID: {id_ativo} | 💻 Hostname: {ativo['hostname']}\n"
                texto += f"🏷️ Tipo: {ativo['tipo']} | 👤 Resp: {ativo['responsavel']} | 📍 Local: {ativo['localizacao']}\n"
                
                if ativo['vulnerabilidades']:
                    texto += f"⚠️ Vulnerabilidades ({qtd_v}):\n"
                    for v in ativo['vulnerabilidades']:
                        texto += f"   • {v['cve']} | Severidade: {v['severidade']} | Status: {v['status']}\n"
                else:
                    texto += "✅ Sem vulnerabilidades associadas.\n"
                
                texto += "─" * 60 + "\n"
                self.caixa_relatorio.insert(ctk.END, texto)

        self.card_ativos.configure(text=f"Total Ativos: {len(base_ativos)}")
        self.card_cves.configure(text=f"Total CVEs: {total_cves}")

        self.caixa_relatorio.configure(state="disabled")

if __name__ == "__main__":
    app = AplicacaoInventario()
    app.mainloop()
