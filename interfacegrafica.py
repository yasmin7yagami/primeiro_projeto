import json
import os
import sys
import io
import re
from enum import Enum
import customtkinter as ctk

# Configuração para terminal do Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Configuração do Tema 🌙 (Dark Mode com fundo Preto)
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
    if not texto:
        return ""
    texto_limpo = re.sub(r'[<>\'\"\\;]', '', texto)
    return texto_limpo.strip()

def validar_cve(cve_texto):
    cve_limpo = cve_texto.strip().upper()
    padrao_cve = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(padrao_cve, cve_limpo))

def validar_hostname(hostname):
    if not hostname or len(hostname) > 63:
        return False
    padrao_hostname = r'^[a-zA-Z0-9.-]+$'
    return bool(re.match(padrao_hostname, hostname))

def validar_id(id_str):
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
# INTERFACE GRÁFICA COM ROLAGEM GERAL 🖥️
# ==========================================
class AplicacaoInventario(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("UFU - CIBERSEGURANÇA 🔒")
        self.geometry("760x840")
        self.configure(fg_color="black")
        
        self.resizable(True, True)
        self.minsize(650, 600)

        carregar_dados()

        # 📜 FRAME DE ROLAGEM PRINCIPAL (Garante rolagem em zoom alto)
        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color="black", bg_color="black")
        self.scroll_container.pack(fill="both", expand=True, padx=5, pady=5)

        # Cabeçalho
        self.header_frame = ctk.CTkFrame(self.scroll_container, corner_radius=10, fg_color="#121212", border_width=1, border_color="#262626")
        self.header_frame.pack(pady=10, padx=10, fill="x")

        self.titulo = ctk.CTkLabel(
            self.header_frame, 
            text="🛡️ UFU - CIBERSEGURANÇA", 
            font=("Segoe UI", 18, "bold"),
            text_color="#60a5fa"
        )
        self.titulo.pack(side="left", padx=15, pady=12)

        # 🔍 Controle de Zoom
        self.frame_zoom = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.frame_zoom.pack(side="right", padx=15)

        ctk.CTkLabel(self.frame_zoom, text="Zoom:", font=("Segoe UI", 11, "bold"), text_color="#d1d5db").pack(side="left", padx=(0, 5))
        
        self.combo_zoom = ctk.CTkOptionMenu(
            self.frame_zoom,
            values=["80%", "100%", "125%", "150%"],
            width=90,
            fg_color="#1f2937",
            button_color="#374151",
            command=self.func_mudar_escala
        )
        self.combo_zoom.set("100%")
        self.combo_zoom.pack(side="left")

        # Sistema de Abas
        self.tabview = ctk.CTkTabview(self.scroll_container, corner_radius=10, fg_color="#09090b", segmented_button_fg_color="#18181b", segmented_button_selected_color="#2563eb")
        self.tabview.pack(pady=5, padx=10, fill="both", expand=True)

        self.tab_ativos = self.tabview.add("💻 Gestão de Ativos")
        self.tab_cve = self.tabview.add("⚠️ Vulnerabilidades")
        self.tab_relatorio = self.tabview.add("📊 Relatório & Busca")

        # Configuração das Abas
        self.setup_aba_ativos()
        self.setup_aba_cve()
        self.setup_aba_relatorio()

        # Barra de Status
        self.lbl_status = ctk.CTkLabel(self.scroll_container, text="🔒 Sistema UFU - Cibersegurança pronto.", font=("Segoe UI", 11, "bold"), text_color="#9ca3af")
        self.lbl_status.pack(pady=8)

        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()

    def func_mudar_escala(self, valor_selecionado):
        escala_map = {"80%": 0.8, "100%": 1.0, "125%": 1.25, "150%": 1.5}
        fator = escala_map.get(valor_selecionado, 1.0)
        ctk.set_widget_scaling(fator)
        self.lbl_status.configure(text=f"🔍 Proporção alterada para {valor_selecionado}.", text_color="#60a5fa")

    # ----------------------------------------------------
    # LAYOUT DAS ABAS
    # ----------------------------------------------------
    def setup_aba_ativos(self):
        # Seleção de Ativo
        frame_select = ctk.CTkFrame(self.tab_ativos, corner_radius=8, fg_color="#121212", border_width=1, border_color="#262626")
        frame_select.pack(pady=5, padx=10, fill="x")

        ctk.CTkLabel(frame_select, text="✏️ Seleção de Ativo para Alterar", font=("Segoe UI", 13, "bold"), text_color="#38bdf8").pack(pady=(8, 4))
        
        sub_select = ctk.CTkFrame(frame_select, fg_color="transparent")
        sub_select.pack(pady=(0, 8))

        self.combo_selecionar_ativo = ctk.CTkOptionMenu(
            sub_select, 
            values=["Nenhum ativo cadastrado"], 
            width=230, 
            fg_color="#18181b", 
            button_color="#27272a"
        )
        self.combo_selecionar_ativo.pack(side="left", padx=5)

        self.btn_carregar_ativo = ctk.CTkButton(sub_select, text="Carregar Dados 📥", fg_color="#0284c7", hover_color="#0369a1", width=120, command=self.func_carregar_dados_ativo)
        self.btn_carregar_ativo.pack(side="left", padx=5)

        self.btn_limpar_form = ctk.CTkButton(sub_select, text="Novo / Limpar 🧹", fg_color="#3f3f46", hover_color="#52525b", width=110, command=self.func_limpar_formulario)
        self.btn_limpar_form.pack(side="left", padx=5)

        # Cadastro / Alteração
        frame_cad = ctk.CTkFrame(self.tab_ativos, corner_radius=8, fg_color="#121212", border_width=1, border_color="#262626")
        frame_cad.pack(pady=5, padx=10, fill="x")

        self.lbl_titulo_form = ctk.CTkLabel(frame_cad, text="Cadastrar Novo Ativo", font=("Segoe UI", 13, "bold"), text_color="#f3f4f6")
        self.lbl_titulo_form.pack(pady=6)

        self.entry_id = ctk.CTkEntry(frame_cad, placeholder_text="ID do Ativo (ex: 101)", width=320, fg_color="#18181b")
        self.entry_id.pack(pady=4)

        self.entry_hostname = ctk.CTkEntry(frame_cad, placeholder_text="Hostname (ex: srv-db-01)", width=320, fg_color="#18181b")
        self.entry_hostname.pack(pady=4)

        self.entry_responsavel = ctk.CTkEntry(frame_cad, placeholder_text="Responsável (ex: Ana Silva)", width=320, fg_color="#18181b")
        self.entry_responsavel.pack(pady=4)

        self.entry_localizacao = ctk.CTkEntry(frame_cad, placeholder_text="Localização (ex: Data Center)", width=320, fg_color="#18181b")
        self.entry_localizacao.pack(pady=4)

        self.combo_tipo = ctk.CTkComboBox(frame_cad, values=[t.value for t in TipoAtivo], width=320, fg_color="#18181b", button_color="#27272a")
        self.combo_tipo.pack(pady=4)

        self.btn_salvar = ctk.CTkButton(frame_cad, text="Salvar Ativo 💾", fg_color="#2563eb", hover_color="#1d4ed8", command=self.func_cadastrar_ativo)
        self.btn_salvar.pack(pady=10)

        # Remoção
        frame_del = ctk.CTkFrame(self.tab_ativos, corner_radius=8, fg_color="#121212", border_width=1, border_color="#262626")
        frame_del.pack(pady=5, padx=10, fill="x")

        ctk.CTkLabel(frame_del, text="Excluir Ativo da Base", font=("Segoe UI", 13, "bold"), text_color="#f87171").pack(pady=4)

        sub_frame = ctk.CTkFrame(frame_del, fg_color="transparent")
        sub_frame.pack(pady=4)

        self.entry_del_id = ctk.CTkEntry(sub_frame, placeholder_text="ID p/ remover", width=160, fg_color="#18181b")
        self.entry_del_id.pack(side="left", padx=5)

        self.btn_deletar = ctk.CTkButton(sub_frame, text="Remover 🗑️", fg_color="#dc2626", hover_color="#991b1b", width=120, command=self.func_deletar_ativo)
        self.btn_deletar.pack(side="left", padx=5)

    def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(self.tab_cve, corner_radius=8, fg_color="#121212", border_width=1, border_color="#262626")
        frame_cve.pack(pady=15, padx=20, fill="x")

        ctk.CTkLabel(frame_cve, text="Vincular Vulnerabilidade (CVE)", font=("Segoe UI", 14, "bold"), text_color="#f3f4f6").pack(pady=10)

        self.entry_cve_id = ctk.CTkEntry(frame_cve, placeholder_text="ID do Ativo Alvo (ex: 101)", width=320, fg_color="#18181b")
        self.entry_cve_id.pack(pady=6)

        self.entry_cve_cod = ctk.CTkEntry(frame_cve, placeholder_text="Código CVE (ex: CVE-2026-1042)", width=320, fg_color="#18181b")
        self.entry_cve_cod.pack(pady=6)

        ctk.CTkLabel(frame_cve, text="Severidade da Vulnerabilidade:", font=("Segoe UI", 11, "bold"), text_color="#d1d5db").pack(pady=(6, 2))
        self.combo_severidade = ctk.CTkComboBox(frame_cve, values=["Baixa", "Média", "Alta", "Crítica"], width=320, fg_color="#18181b", button_color="#27272a")
        self.combo_severidade.set("Alta")
        self.combo_severidade.pack(pady=4)

        ctk.CTkLabel(frame_cve, text="Status da Vulnerabilidade:", font=("Segoe UI", 11, "bold"), text_color="#d1d5db").pack(pady=(6, 2))
        self.combo_status_cve = ctk.CTkComboBox(frame_cve, values=["Identificada", "Em Análise", "Em Correção", "Mitigada", "Corrigida"], width=320, fg_color="#18181b", button_color="#27272a")
        self.combo_status_cve.set("Identificada")
        self.combo_status_cve.pack(pady=4)

        self.btn_add_cve = ctk.CTkButton(frame_cve, text="Vincular CVE 🔗", fg_color="#d97706", hover_color="#b45309", width=200, command=self.func_adicionar_cve)
        self.btn_add_cve.pack(pady=15)

    def setup_aba_relatorio(self):
        self.frame_cards = ctk.CTkFrame(self.tab_relatorio, fg_color="transparent")
        self.frame_cards.pack(pady=5, fill="x")

        self.card_ativos = ctk.CTkLabel(self.frame_cards, text="Ativos: 0", font=("Segoe UI", 12, "bold"), fg_color="#18181b", text_color="#60a5fa", corner_radius=6, width=150, height=30)
        self.card_ativos.pack(side="left", padx=10, expand=True)

        self.card_cves = ctk.CTkLabel(self.frame_cards, text="CVEs: 0", font=("Segoe UI", 12, "bold"), fg_color="#18181b", text_color="#f87171", corner_radius=6, width=150, height=30)
        self.card_cves.pack(side="right", padx=10, expand=True)

        frame_busca = ctk.CTkFrame(self.tab_relatorio, fg_color="transparent")
        frame_busca.pack(pady=5, padx=5, fill="x")

        self.entry_busca = ctk.CTkEntry(frame_busca, placeholder_text="🔍 Buscar por ID, Hostname, Resp., Local ou CVE...", width=380, fg_color="#18181b")
        self.entry_busca.pack(side="left", padx=(0, 5), expand=True, fill="x")
        self.entry_busca.bind("<KeyRelease>", lambda event: self.func_buscar_ativos())

        self.btn_limpar_busca = ctk.CTkButton(frame_busca, text="Limpar ✖", width=90, fg_color="#27272a", hover_color="#3f3f46", command=self.func_limpar_busca)
        self.btn_limpar_busca.pack(side="right")

        self.caixa_relatorio = ctk.CTkTextbox(self.tab_relatorio, height=350, font=("Consolas", 12), fg_color="#121212", text_color="#e4e4e7", border_width=1, border_color="#262626")
        self.caixa_relatorio.pack(pady=5, padx=5, fill="both", expand=True)
        self.caixa_relatorio.configure(state="disabled")

    # ----------------------------------------------------
    # REGRAS DE SELEÇÃO E EDIÇÃO DE ATIVOS ✏️
    # ----------------------------------------------------
    def func_atualizar_menu_selecao(self):
        if not base_ativos:
            opcoes = ["Nenhum ativo cadastrado"]
        else:
            opcoes = [f"ID {k} - {v['hostname']}" for k, v in base_ativos.items()]

        self.combo_selecionar_ativo.configure(values=opcoes)
        self.combo_selecionar_ativo.set(opcoes[0])

    def func_carregar_dados_ativo(self):
        item_selecionado = self.combo_selecionar_ativo.get()

        if item_selecionado == "Nenhum ativo cadastrado" or not item_selecionado:
            self.lbl_status.configure(text="⚠️ Selecione um ativo válido para carregar!", text_color="#facc15")
            return

        try:
            id_str = item_selecionado.split(" ")[1]
            id_val = int(id_str)
        except (IndexError, ValueError):
            self.lbl_status.configure(text="⚠️ Erro ao identificar o ID selecionado.", text_color="#f87171")
            return

        if id_val in base_ativos:
            ativo = base_ativos[id_val]

            self.func_limpar_formulario()
            self.entry_id.insert(0, str(id_val))
            self.entry_id.configure(state="disabled")

            self.entry_hostname.insert(0, ativo.get("hostname", ""))
            self.entry_responsavel.insert(0, ativo.get("responsavel", ""))
            self.entry_localizacao.insert(0, ativo.get("localizacao", ""))
            self.combo_tipo.set(ativo.get("tipo", TipoAtivo.SERVIDORES.value))

            self.lbl_titulo_form.configure(text=f"✏️ Alterar Ativo ID: {id_val}", text_color="#38bdf8")
            self.btn_salvar.configure(text="Atualizar Ativo 🔄", fg_color="#059669", hover_color="#047857")
            self.lbl_status.configure(text=f"📥 Dados do Ativo ID {id_val} carregados para edição.", text_color="#60a5fa")

    def func_limpar_formulario(self):
        self.entry_id.configure(state="normal")
        self.entry_id.delete(0, 'end')
        self.entry_hostname.delete(0, 'end')
        self.entry_responsavel.delete(0, 'end')
        self.entry_localizacao.delete(0, 'end')

        self.lbl_titulo_form.configure(text="Cadastrar Novo Ativo", text_color="#f3f4f6")
        self.btn_salvar.configure(text="Salvar Ativo 💾", fg_color="#2563eb", hover_color="#1d4ed8")

    # ----------------------------------------------------
    # REGRAS DE NEGÓCIO 💾
    # ----------------------------------------------------
    def func_cadastrar_ativo(self):
        self.entry_id.configure(state="normal")
        raw_id = self.entry_id.get().strip()

        valido, res_id = validar_id(raw_id)
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
        self.lbl_status.configure(text=f"✅ Ativo {id_val} gravado/atualizado com sucesso!", text_color="#4ade80")
        
        self.func_atualizar_relatorio()
        self.func_atualizar_menu_selecao()
        self.func_limpar_formulario()

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
        self.lbl_status.configure(text=f"✅ CVE '{cve_cod}' associada ao Ativo {id_val}!", text_color="#4ade80")
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
            self.func_atualizar_menu_selecao()
            self.func_limpar_formulario()
            self.entry_del_id.delete(0, 'end')
        else:
            self.lbl_status.configure(text="⚠️ Ativo não encontrado!", text_color="#facc15")

    def func_buscar_ativos(self):
        termo = sanitizar_texto(self.entry_busca.get()).lower()

        if not termo:
            self.func_atualizar_relatorio()
            return

        self.caixa_relatorio.configure(state="normal")
        self.caixa_relatorio.delete("1.0", ctk.END)

        encontrados = 0
        total_cves_filtro = 0

        for id_ativo, ativo in base_ativos.items():
            cves_str = " ".join([v['cve'].lower() for v in ativo.get('vulnerabilidades', [])])

            if (termo in str(id_ativo).lower() or
                termo in ativo['hostname'].lower() or
                termo in ativo['responsavel'].lower() or
                termo in ativo['localizacao'].lower() or
                termo in ativo['tipo'].lower() or
                termo in cves_str):

                encontrados += 1
                qtd_v = len(ativo.get('vulnerabilidades', []))
                total_cves_filtro += qtd_v

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

        if encontrados == 0:
            self.caixa_relatorio.insert(ctk.END, f"🔍 Nenhum ativo encontrado para o termo: '{termo}'\n")

        self.card_ativos.configure(text=f"Exibindo: {encontrados}/{len(base_ativos)}")
        self.card_cves.configure(text=f"CVEs no Filtro: {total_cves_filtro}")

        self.caixa_relatorio.configure(state="disabled")

    def func_limpar_busca(self):
        self.entry_busca.delete(0, 'end')
        self.func_atualizar_relatorio()

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