# ==========================================
# 🚦 TRADUTOR DE SEVERIDADE DE CVE
# ==========================================
def traduzir_severidade(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return (
                "🚨 CRÍTICO (Ação Urgente!)",
                "#ef4444",
                "💡 Ação Recomendada: Aplicar patch de segurança IMEDIATAMENTE e isolar o ativo se possível.",
            )
        elif score >= 7.0:
            return (
                "⚠️ ALTO (Atenção Prioritária)",
                "#f97316",
                "💡 Ação Recomendada: Agendar atualização do software o quanto antes.",
            )
        elif score >= 4.0:
            return (
                "🟡 MÉDIO (Planejar Correção)",
                "#eab308",
                "💡 Ação Recomendada: Corrigir na próxima janela de manutenção programada.",
            )
        else:
            return (
                "🟢 BAIXO (Risco Reduzido)",
                "#10b981",
                "💡 Ação Recomendada: Monitorar o ativo; correção opcional.",
            )
    except ValueError:
        return (
            "❓ Desconhecido / Não Avaliado",
            "#94a3b8",
            "💡 Ação Recomendada: Consultar a documentação do fornecedor do software.",
        )


# ==========================================
# 🌐 INTEGRAÇÃO COM API NVD/NIST + CACHE + TRADUÇÃO
# ==========================================
def consultar_cve_nvd(codigo_cve):
    codigo_limpo = codigo_cve.strip().upper()

    # 1. Validação Prévia 🔍
    if not validar_cve(codigo_limpo):
        return {
            "erro": "Formato de CVE inválido! Use o padrão: CVE-AAAA-NNNN (ex: CVE-2021-44228)"
        }

    # 2. Busca no Cache Local 💾
    cves_locais = carregar_cves_locais()
    if codigo_limpo in cves_locais:
        dados_cache = cves_locais[codigo_limpo]
        dados_cache["origem"] = "local"
        return dados_cache

    # 3. Consulta à API da NVD 🌐
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={codigo_limpo}"
    headers = {"User-Agent": "MeuAppPython/1.0"}

    try:
        resposta = requests.get(url, headers=headers, timeout=10)
        if resposta.status_code == 200:
            dados = resposta.json()
            vulnerabilidades = dados.get("vulnerabilities", [])

            if not vulnerabilidades:
                return {
                    "erro": "Vulnerabilidade não encontrada na base de dados oficial da NVD."
                }

            cve_data = vulnerabilidades[0].get("cve", {})

            descriptions = cve_data.get("descriptions", [])
            descricao_en = "Descrição não disponível."
            for d in descriptions:
                if d.get("lang") == "en":
                    descricao_en = d.get("value")
                    break

            metrics = cve_data.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [])
            cvss_score = (
                cvss_data[0].get("cvssData", {}).get("baseScore", "N/A")
                if cvss_data
                else "N/A"
            )

            # 4. Tradução Automática para Português 🔤
            descricao_pt = traduzir_texto(descricao_en)

            estrutura_cve = {
                "id": codigo_limpo,
                "cvss": cvss_score,
                "descricao_en": descricao_en,
                "descricao": descricao_pt,
                "origem": "api",
            }

            # 5. Guarda no Cache Local para futuras pesquisas 💾
            guardar_cve_local(codigo_limpo, estrutura_cve)

            return estrutura_cve
        else:
            return {
                "erro": f"Erro na resposta da NVD. Código HTTP: {resposta.status_code}"
            }
    except Exception as e:
        return {"erro": f"Falha na conexão com a NVD: {e}"}
    
    
    # ==========================================
    # ABA DE GESTÃO DE VULNERABILIDADES (CVE)
    # ==========================================
def setup_aba_cve(self):
        frame_cve = ctk.CTkFrame(
            self.tab_cve,
            corner_radius=8,
            fg_color="#090d14",
            border_width=1,
            border_color=COR_BORDA,
        )
        frame_cve.pack(pady=15, padx=15, fill="x")

        ctk.CTkLabel(
            frame_cve,
            text="⚠️ Vincular / Consultar Vulnerabilidade CVE",
            font=("Segoe UI", 16, "bold"),
            text_color="#facc15",
        ).pack(pady=(10, 4))

        self.cve_entry_id = ctk.CTkEntry(
            frame_cve,
            placeholder_text="ID do Ativo Alvo (ex: 101)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cve_entry_id.pack(pady=5)

        self.cve_entry_codigo = ctk.CTkEntry(
            frame_cve,
            placeholder_text="Código CVE (ex: CVE-2021-44228)",
            width=320,
            fg_color="#101720",
            border_color=COR_BORDA,
        )
        self.cve_entry_codigo.pack(pady=5)

        frame_btns_cve = ctk.CTkFrame(frame_cve, fg_color="transparent")
        frame_btns_cve.pack(pady=10)

        ctk.CTkButton(
            frame_btns_cve,
            text="Buscar / Processar CVE 🔍",
            fg_color=COR_AZUL_PRINCIPAL,
            hover_color=COR_AZUL_HOVER,
            width=180,
            command=self.func_buscar_cve_api,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            frame_btns_cve,
            text="Vincular ao Ativo 🔗",
            fg_color=COR_VERDE_NEON,
            hover_color=COR_VERDE_HOVER,
            text_color="#022c22",
            width=150,
            command=self.func_vincular_cve,
        ).pack(side="left", padx=5)

        self.txt_cve_info = ctk.CTkTextbox(
            frame_cve,
            width=550,
            height=160,
            fg_color="#05070a",
            border_color=COR_BORDA,
            border_width=1,
        )
        self.txt_cve_info.pack(pady=10)
        self.txt_cve_info.insert(
            "1.0", "O resultado da consulta aparecerá aqui..."
        )

def func_buscar_cve_api(self):
        cve_code = self.cve_entry_codigo.get().strip().upper()

        if not cve_code:
            messagebox.showwarning(
                "Aviso", "Por favor, digite um código de CVE!"
            )
            return

        self.lbl_status.configure(
            text="⏳ A processar validação, cache e API NVD...",
            text_color=COR_TEXTO_DEST,
        )
        self.update_idletasks()

        # Executa o fluxo unificado (Validação -> Cache Local -> API -> Tradução -> Salvar)
        dados = consultar_cve_nvd(cve_code)
        self.txt_cve_info.delete("1.0", "end")

        if "erro" not in dados:
            rotulo, cor_hex, dica_acao = traduzir_severidade(dados["cvss"])
            origem_str = (
                "⚡ [CACHE LOCAL]"
                if dados.get("origem") == "local"
                else "🌐 [API NVD (Em Tempo Real)]"
            )

            res_texto = (
                f"📌 ID CVE: {dados['id']} ({origem_str})\n"
                f"📊 Pontuação CVSS: {dados['cvss']} / 10.0\n"
                f"🚨 Nível de Risco: {rotulo}\n"
                f"{dica_acao}\n\n"
                f"📝 Descrição (Português):\n{dados['descricao']}"
            )

            self.txt_cve_info.insert("1.0", res_texto)
            self.lbl_status.configure(
                text=f"✅ {dados['id']} processada! Severidade: {rotulo}",
                text_color=cor_hex,
            )
        else:
            self.txt_cve_info.insert("1.0", f"❌ Erro: {dados['erro']}")
            self.lbl_status.configure(
                text=f"❌ Erro na consulta.", text_color="#ef4444"
            )

def func_vincular_cve(self):
        valido, res_id = validar_id(self.cve_entry_id.get().strip())
        if not valido or res_id not in base_ativos:
            messagebox.showerror(
                "Erro", "ID de ativo inválido ou não encontrado!"
            )
            return

        cve_code = self.cve_entry_codigo.get().strip().upper()
        if not validar_cve(cve_code):
            messagebox.showerror("Erro", "Formato de CVE inválido!")
            return

        if cve_code in base_ativos[res_id]["vulnerabilidades"]:
            messagebox.showwarning(
                "Aviso", "Esta CVE já está vinculada a este ativo."
            )
            return

        base_ativos[res_id]["vulnerabilidades"].append(cve_code)
        salvar_dados_ativos()

        self.lbl_status.configure(
            text=f"✅ {cve_code} vinculada ao Ativo ID {res_id}!",
            text_color=COR_TEXTO_VERDE,
        )
        self.func_atualizar_relatorio()

