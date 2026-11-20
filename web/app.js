class InventarioApp {
  constructor() {
    this.usuarioLogado = null;
    this.ativos = [];
    this.dadosRisco = null;
    this.cveAtualConsultada = null;

    window.addEventListener("DOMContentLoaded", () => {
      this.registrarEventos();
      this.inicializar();
    });
  }

  registrarEventos() {
    document.getElementById("form-login").addEventListener("submit", (e) => {
      e.preventDefault();
      this.efetuarLogin();
    });

    document.getElementById("btn-abrir-modal-senha").addEventListener("click", () => this.abrirModalSenha());
    document.getElementById("btn-logout").addEventListener("click", () => this.efetuarLogout());

    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const aba = btn.dataset.tab;
        if (aba) this.mudarAba(aba);
      });
    });

    document.getElementById("filtro-busca").addEventListener("input", () => this.filtrarTabela());
    document.getElementById("btn-limpar-filtro").addEventListener("click", () => this.limparFiltro());
    document.getElementById("btn-abrir-matrizes").addEventListener("click", () => this.abrirModalMatrizes());
    document.getElementById("btn-recalcular-risco").addEventListener("click", () => this.carregarDados());

    document.getElementById("form-cadastrar").addEventListener("submit", (e) => {
      e.preventDefault();
      this.salvarNovoAtivo();
    });
    document.getElementById("cad-tipo").addEventListener("change", () => this.atualizarCamposDinamicos("cad"));

    document.getElementById("sel-ativo-gerenciar").addEventListener("change", () => this.carregarDadosParaEdicao());
    document.getElementById("form-editar").addEventListener("submit", (e) => {
      e.preventDefault();
      this.salvarEdicaoAtivo();
    });
    document.getElementById("btn-vincular-dependencia").addEventListener("click", () => this.adicionarDependencia());
    document.getElementById("btn-excluir-ativo").addEventListener("click", () => this.excluirAtivoSelecionado());

    document.getElementById("btn-consultar-nvd").addEventListener("click", () => this.consultarNVD());
    document.getElementById("btn-vincular-cve").addEventListener("click", () => this.vincularCveAoAtivo());

    document.getElementById("form-novo-usuario").addEventListener("submit", (e) => {
      e.preventDefault();
      this.cadastrarUsuario();
    });

    document.getElementById("btn-fechar-modal-senha").addEventListener("click", () => this.fecharModalSenha());
    document.getElementById("btn-cancelar-modal-senha").addEventListener("click", () => this.fecharModalSenha());
    document.getElementById("form-alterar-senha").addEventListener("submit", (e) => {
      e.preventDefault();
      this.confirmarAlteracaoSenha();
    });

    document.getElementById("btn-fechar-modal-matrizes").addEventListener("click", () => this.fecharModalMatrizes());
  }

  async apiFetch(url, options = {}) {
    const config = {
      credentials: "same-origin",
      ...options,
      headers: {
        ...(options.headers || {}),
      },
    };
    const res = await fetch(url, config);
    if (res.status === 401 && url !== "/api/login" && url !== "/api/me") {
      this.usuarioLogado = null;
      this.exibirLogin();
      this.mostrarToast("Sessão expirada. Faça login novamente.", "error");
    }
    return res;
  }

  async inicializar() {
    localStorage.removeItem("sessao_ciberseguranca");
    try {
      const res = await this.apiFetch("/api/me");
      if (res.ok) {
        const data = await res.json();
        if (data.sucesso && data.usuario) {
          this.usuarioLogado = data.usuario;
          this.exibirAplicacao();
          return;
        }
      }
    } catch (e) {
      // Sem sessão ativa
    }
    this.exibirLogin();
  }

  async efetuarLogin() {
    const usuario = document.getElementById("login-usuario").value.trim();
    const senha = document.getElementById("login-senha").value;

    if (!usuario || !senha) {
      this.mostrarToast("Informe usuário e senha!", "error");
      return;
    }

    try {
      const res = await this.apiFetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usuario, senha }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.usuarioLogado = data.usuario;
        document.getElementById("login-senha").value = "";
        this.mostrarToast(`Bem-vindo(a), ${this.usuarioLogado.nome}!`, "success");
        this.exibirAplicacao();
      } else {
        this.mostrarToast(data.mensagem || "Credenciais incorretas!", "error");
      }
    } catch (err) {
      this.mostrarToast("Falha na comunicação com o servidor.", "error");
    }
  }

  async efetuarLogout() {
    try {
      await this.apiFetch("/api/logout", { method: "POST" });
    } catch (e) {
      // Prossegue limpando estado local
    }
    this.usuarioLogado = null;
    this.ativos = [];
    this.dadosRisco = null;
    this.exibirLogin();
    this.mostrarToast("Sessão finalizada com sucesso.", "info");
  }

  exibirLogin() {
    document.getElementById("login-overlay").style.display = "flex";
    document.getElementById("app-container").style.display = "none";
  }

  exibirAplicacao() {
    document.getElementById("login-overlay").style.display = "none";
    document.getElementById("app-container").style.display = "block";

    document.getElementById("header-user-name").textContent = `👤 ${this.usuarioLogado.nome}`;
    const badgeRole = document.getElementById("header-user-role");
    badgeRole.textContent = String(this.usuarioLogado.role || "user").toUpperCase();
    badgeRole.className = `badge ${this.usuarioLogado.role === "admin" ? "badge-success" : "badge-role"}`;

    const tabAdmin = document.getElementById("tab-btn-usuarios");
    tabAdmin.style.display = this.usuarioLogado.role === "admin" ? "inline-block" : "none";

    this.mudarAba("dashboard");
    this.carregarDados();
  }

  mudarAba(nomeAba) {
    document.querySelectorAll(".nav-tab").forEach((tab) => tab.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((pane) => pane.classList.remove("active"));

    const btnTab = document.querySelector(`.nav-tab[data-tab="${nomeAba}"]`);
    if (btnTab) btnTab.classList.add("active");

    const targetPane = document.getElementById(`aba-${nomeAba}`);
    if (targetPane) targetPane.classList.add("active");

    if (nomeAba === "usuarios" && this.usuarioLogado && this.usuarioLogado.role === "admin") {
      this.carregarUsuarios();
    }
  }

  async carregarDados() {
    try {
      const resHealth = await this.apiFetch("/api/health");
      if (resHealth.ok) {
        const health = await resHealth.json();
        const horas = health.uptime_horas || 0;
        document.getElementById("metric-uptime").textContent = `${horas}h online`;
      }

      const resAtivos = await this.apiFetch("/api/ativos");
      if (!resAtivos.ok) return;
      const dataAtivos = await resAtivos.json();
      this.ativos = dataAtivos.ativos || [];
      document.getElementById("metric-total-ativos").textContent = String(this.ativos.length);

      const resRisco = await this.apiFetch("/api/risco");
      if (!resRisco.ok) return;
      this.dadosRisco = await resRisco.json();

      if (this.dadosRisco.sucesso) {
        const metricInv = document.getElementById("metric-invertivel");
        metricInv.textContent = this.dadosRisco.invertivel ? "Sim ✅" : "Não ❌";
        metricInv.className = `metric-value ${this.dadosRisco.invertivel ? "text-success" : "text-danger"}`;
        document.getElementById("metric-det-sub").textContent = `det(I - A) = ${Number(this.dadosRisco.determinante).toFixed(4)}`;
        document.getElementById("metric-total-cves").textContent = `${(this.dadosRisco.vulnerabilidades_cves || []).length} CVEs`;
      }

      this.renderizarTabelaInventario();
      this.atualizarSelectsAtivos();
    } catch (err) {
      console.error(err);
      this.mostrarToast("Erro ao carregar dados do sistema.", "error");
    }
  }

  renderizarTabelaInventario() {
    const tbody = document.getElementById("tbody-inventario");
    tbody.textContent = "";

    if (!this.ativos || this.ativos.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 10;
      td.style.textAlign = "center";
      td.style.color = "var(--text-muted)";
      td.textContent = "Nenhum ativo cadastrado no momento.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const mapaRisco = {};
    if (this.dadosRisco && this.dadosRisco.tabela) {
      this.dadosRisco.tabela.forEach((item) => {
        mapaRisco[item.id] = {
          risco_proprio: Number(item.risco_proprio || 0),
          risco_efetivo: Number(item.risco_efetivo || 0),
          fator_exposicao: Number(item.fator_exposicao || 1.0),
        };
      });
    }

    this.ativos.forEach((ativo) => {
      const id = ativo.id_ativo || ativo.id;
      const risco = mapaRisco[id] || { risco_proprio: 0, risco_efetivo: 0, fator_exposicao: 1.0 };

      const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      const strongId = document.createElement("strong");
      strongId.textContent = String(id);
      tdId.appendChild(strongId);
      tr.appendChild(tdId);

      const tdHost = document.createElement("td");
      tdHost.textContent = ativo.hostname || "";
      tr.appendChild(tdHost);

      const tdTipo = document.createElement("td");
      const badgeTipo = document.createElement("span");
      badgeTipo.className = "badge badge-role";
      badgeTipo.textContent = ativo.tipo || "";
      tdTipo.appendChild(badgeTipo);
      tr.appendChild(tdTipo);

      const tdResp = document.createElement("td");
      tdResp.textContent = ativo.responsavel || "";
      tr.appendChild(tdResp);

      const tdLoc = document.createElement("td");
      tdLoc.textContent = ativo.localizacao || "";
      tr.appendChild(tdLoc);

      const tdVuls = document.createElement("td");
      const vuls = ativo.vulnerabilidades || [];
      if (vuls.length > 0) {
        vuls.forEach((cve) => {
          const span = document.createElement("span");
          span.className = "badge badge-cvss";
          span.style.margin = "2px";
          span.textContent = cve;
          tdVuls.appendChild(span);
          tdVuls.appendChild(document.createTextNode(" "));
        });
      } else {
        const spanVazio = document.createElement("span");
        spanVazio.style.color = "var(--text-muted)";
        spanVazio.textContent = "Nenhuma";
        tdVuls.appendChild(spanVazio);
      }
      tr.appendChild(tdVuls);

      const tdFator = document.createElement("td");
      tdFator.textContent = `${risco.fator_exposicao}x`;
      tr.appendChild(tdFator);

      const tdRiscoProprio = document.createElement("td");
      tdRiscoProprio.className = "risco-proprio";
      tdRiscoProprio.textContent = risco.risco_proprio.toFixed(2);
      tr.appendChild(tdRiscoProprio);

      const tdRiscoEfetivo = document.createElement("td");
      tdRiscoEfetivo.className = "risco-efetivo";
      tdRiscoEfetivo.textContent = risco.risco_efetivo.toFixed(2);
      tr.appendChild(tdRiscoEfetivo);

      const tdDeps = document.createElement("td");
      const depsEntries = Object.entries(ativo.dependencias || {});
      if (depsEntries.length > 0) {
        depsEntries.forEach(([targetId, peso]) => {
          const chip = document.createElement("span");
          chip.className = "chip";
          chip.style.fontSize = "11px";
          chip.appendChild(document.createTextNode(`ID ${targetId}: `));
          const strongPeso = document.createElement("strong");
          strongPeso.textContent = `${Math.round(Number(peso) * 100)}%`;
          chip.appendChild(strongPeso);
          tdDeps.appendChild(chip);
          tdDeps.appendChild(document.createTextNode(" "));
        });
      } else {
        const spanSemDep = document.createElement("span");
        spanSemDep.style.color = "var(--text-muted)";
        spanSemDep.style.fontSize = "12px";
        spanSemDep.textContent = "Nenhuma";
        tdDeps.appendChild(spanSemDep);
      }
      tr.appendChild(tdDeps);

      tbody.appendChild(tr);
    });
  }

  filtrarTabela() {
    const termo = document.getElementById("filtro-busca").value.toLowerCase().trim();
    const linhas = document.querySelectorAll("#tbody-inventario tr");

    linhas.forEach((linha) => {
      const texto = linha.textContent.toLowerCase();
      linha.style.display = texto.includes(termo) ? "" : "none";
    });
  }

  limparFiltro() {
    document.getElementById("filtro-busca").value = "";
    this.filtrarTabela();
  }

  atualizarCamposDinamicos(prefixo) {
    const selectTipo = document.getElementById(`${prefixo}-tipo`);
    const label1 = document.getElementById(`${prefixo}-label-dinamico-1`);
    const input1 = document.getElementById(`${prefixo}-input-dinamico-1`);
    if (!selectTipo || !label1 || !input1) return;

    const tipo = selectTipo.value;
    const linha2 = document.getElementById(`${prefixo}-linha-dinamica-2`);
    const label2 = document.getElementById(`${prefixo}-label-dinamico-2`);
    const input2 = document.getElementById(`${prefixo}-input-dinamico-2`);

    if (tipo === "Servidores") {
      label1.textContent = "Sistema Operacional";
      input1.placeholder = "Ex: Linux Ubuntu / Debian Server";
      if (linha2) linha2.style.display = "flex";
      if (label2) label2.textContent = "Função do Servidor";
      if (input2) input2.placeholder = "Ex: Servidor de Aplicação / Banco de Dados";
    } else if (tipo === "Roteadores/Switches") {
      label1.textContent = "Quantidade de Portas";
      input1.placeholder = "Ex: 24 ou 48";
      if (linha2) linha2.style.display = "flex";
      if (label2) label2.textContent = "Camada de Rede (Layer)";
      if (input2) input2.placeholder = "Ex: L2 ou L3";
    } else if (tipo === "Computadores") {
      label1.textContent = "Sistema Operacional";
      input1.placeholder = "Ex: Windows 11 / Ubuntu Desktop";
      if (linha2) linha2.style.display = "flex";
      if (label2) label2.textContent = "Departamento";
      if (input2) input2.placeholder = "Ex: Engenharia / SOC";
    } else if (tipo === "Impressoras") {
      label1.textContent = "Tipo de Impressão";
      input1.placeholder = "Ex: Laser Corporativa / Térmica";
      if (linha2) linha2.style.display = "none";
    }
  }

  async salvarNovoAtivo() {
    const id_ativo = parseInt(document.getElementById("cad-id").value, 10);
    const hostname = document.getElementById("cad-hostname").value.trim();
    const responsavel = document.getElementById("cad-responsavel").value.trim();
    const localizacao = document.getElementById("cad-localizacao").value.trim();
    const tipo = document.getElementById("cad-tipo").value;

    const payload = { id_ativo, hostname, responsavel, localizacao, tipo };

    if (tipo === "Servidores") {
      payload.sistema_operacional = document.getElementById("cad-input-dinamico-1").value.trim();
      payload.funcao = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Roteadores/Switches") {
      payload.qtd_portas = parseInt(document.getElementById("cad-input-dinamico-1").value, 10) || 24;
      payload.camada = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Computadores") {
      payload.sistema_operacional = document.getElementById("cad-input-dinamico-1").value.trim();
      payload.departamento = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Impressoras") {
      payload.tipo_impressao = document.getElementById("cad-input-dinamico-1").value.trim();
    }

    try {
      const res = await this.apiFetch("/api/ativos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast(`Equipamento ${hostname} cadastrado com sucesso!`, "success");
        document.getElementById("form-cadastrar").reset();
        await this.carregarDados();
        this.mudarAba("dashboard");
      } else {
        this.mostrarToast(data.mensagem || "Erro ao cadastrar equipamento.", "error");
      }
    } catch (err) {
      this.mostrarToast("Falha na comunicação com o servidor.", "error");
    }
  }

  _preencherSelect(selectEl, placeholderText, valorAnterior) {
    selectEl.textContent = "";
    const optPadrao = document.createElement("option");
    optPadrao.value = "";
    optPadrao.textContent = placeholderText;
    selectEl.appendChild(optPadrao);

    this.ativos.forEach((a) => {
      const id = a.id_ativo || a.id;
      const opt = document.createElement("option");
      opt.value = String(id);
      opt.textContent = `[ID ${id}] ${a.hostname} (${a.tipo})`;
      selectEl.appendChild(opt);
    });

    if (valorAnterior) {
      selectEl.value = valorAnterior;
    }
  }

  atualizarSelectsAtivos() {
    const selectGerenciar = document.getElementById("sel-ativo-gerenciar");
    const selectVincular = document.getElementById("sel-ativo-vincular-cve");
    const selectDepAlvo = document.getElementById("sel-dependencia-alvo");

    this._preencherSelect(selectGerenciar, "-- Escolha um ativo da lista --", selectGerenciar.value);
    this._preencherSelect(selectVincular, "-- Selecione o ativo --", selectVincular.value);
    this._preencherSelect(selectDepAlvo, "-- Selecione o equipamento --", "");
  }

  carregarDadosParaEdicao() {
    const idSelecionado = document.getElementById("sel-ativo-gerenciar").value;
    const box = document.getElementById("box-edicao-ativo");

    if (!idSelecionado) {
      box.style.display = "none";
      return;
    }

    const ativo = this.ativos.find((a) => String(a.id_ativo || a.id) === String(idSelecionado));
    if (!ativo) {
      box.style.display = "none";
      return;
    }

    box.style.display = "block";
    document.getElementById("edit-id").value = String(idSelecionado);
    document.getElementById("edit-hostname").value = ativo.hostname || "";
    document.getElementById("edit-responsavel").value = ativo.responsavel || "";
    document.getElementById("edit-localizacao").value = ativo.localizacao || "";
    document.getElementById("edit-tipo").value = ativo.tipo || "Servidores";

    this.renderizarChipsDependencias(ativo);
  }

  renderizarChipsDependencias(ativo) {
    const container = document.getElementById("lista-dependencias-ativo");
    container.textContent = "";

    const entries = Object.entries(ativo.dependencias || {});

    if (entries.length === 0) {
      const vazio = document.createElement("span");
      vazio.style.color = "var(--text-muted)";
      vazio.style.fontSize = "12px";
      vazio.textContent = "Nenhuma dependência cadastrada para este ativo.";
      container.appendChild(vazio);
      return;
    }

    entries.forEach(([targetId, peso]) => {
      const targetAtivo = this.ativos.find((a) => String(a.id_ativo || a.id) === String(targetId));
      const targetName = targetAtivo ? targetAtivo.hostname : `ID ${targetId}`;

      const chip = document.createElement("div");
      chip.className = "chip";

      const texto = document.createElement("span");
      texto.appendChild(document.createTextNode("Depende de "));
      const strongNome = document.createElement("strong");
      strongNome.textContent = targetName;
      texto.appendChild(strongNome);
      texto.appendChild(document.createTextNode(`: ${(Number(peso) * 100).toFixed(0)}% do risco`));

      const btnRemover = document.createElement("span");
      btnRemover.className = "chip-remove";
      btnRemover.textContent = "×";
      btnRemover.addEventListener("click", () => this.removerDependencia(targetId));

      chip.appendChild(texto);
      chip.appendChild(btnRemover);
      container.appendChild(chip);
    });
  }

  async adicionarDependencia() {
    const idOrigem = document.getElementById("edit-id").value;
    const idAlvo = document.getElementById("sel-dependencia-alvo").value;
    const peso = parseFloat(document.getElementById("input-dependencia-peso").value);

    if (!idAlvo || isNaN(peso) || peso <= 0 || peso >= 1.0) {
      this.mostrarToast("Informe o equipamento alvo e uma fração válida entre 0.01 e 0.99!", "error");
      return;
    }

    if (String(idOrigem) === String(idAlvo)) {
      this.mostrarToast("Um equipamento não pode depender de si mesmo (A_ii = 0)!", "error");
      return;
    }

    try {
      const res = await this.apiFetch(`/api/ativos/${encodeURIComponent(idOrigem)}/dependencias`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_alvo: parseInt(idAlvo, 10), peso }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast("Dependência registrada!", "success");
        await this.carregarDados();
        this.carregarDadosParaEdicao();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao registrar dependência.", "error");
      }
    } catch (e) {
      this.mostrarToast("Falha ao registrar dependência.", "error");
    }
  }

  async removerDependencia(idAlvo) {
    const idOrigem = document.getElementById("edit-id").value;
    try {
      const res = await this.apiFetch(
        `/api/ativos/${encodeURIComponent(idOrigem)}/dependencias/${encodeURIComponent(idAlvo)}`,
        { method: "DELETE" }
      );
      const data = await res.json();
      if (res.ok && data.sucesso) {
        this.mostrarToast("Dependência removida!", "info");
        await this.carregarDados();
        this.carregarDadosParaEdicao();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao remover dependência.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao remover dependência.", "error");
    }
  }

  async salvarEdicaoAtivo() {
    const id_ativo = document.getElementById("edit-id").value;
    const hostname = document.getElementById("edit-hostname").value.trim();
    const responsavel = document.getElementById("edit-responsavel").value.trim();
    const localizacao = document.getElementById("edit-localizacao").value.trim();
    const tipo = document.getElementById("edit-tipo").value;

    try {
      const res = await this.apiFetch(`/api/ativos/${encodeURIComponent(id_ativo)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname, responsavel, localizacao, tipo }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast("Ativo atualizado com sucesso!", "success");
        await this.carregarDados();
        this.carregarDadosParaEdicao();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao atualizar ativo.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro na atualização do ativo.", "error");
    }
  }

  async excluirAtivoSelecionado() {
    const id = document.getElementById("edit-id").value;
    if (!confirm(`Deseja realmente excluir permanentemente o Ativo ID ${id}?`)) return;

    try {
      const res = await this.apiFetch(`/api/ativos/${encodeURIComponent(id)}`, { method: "DELETE" });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast(`Ativo ID ${id} excluído com sucesso!`, "success");
        document.getElementById("box-edicao-ativo").style.display = "none";
        document.getElementById("sel-ativo-gerenciar").value = "";
        await this.carregarDados();
      } else {
        this.mostrarToast(data.mensagem || "Falha ao excluir ativo.", "error");
      }
    } catch (e) {
      this.mostrarToast("Falha ao se comunicar com o servidor.", "error");
    }
  }

  async consultarNVD() {
    const codigo = document.getElementById("input-cve-busca").value.trim().toUpperCase();
    if (!codigo) {
      this.mostrarToast("Digite o código da CVE (ex: CVE-2021-44228)!", "error");
      return;
    }

    const card = document.getElementById("card-cve-resultado");
    card.style.display = "none";
    this.mostrarToast(`Consultando NVD oficial para ${codigo}...`, "info");

    try {
      const res = await this.apiFetch(`/api/cve/consultar?codigo=${encodeURIComponent(codigo)}`);
      const data = await res.json();

      if (!res.ok || data.erro) {
        this.mostrarToast(data.erro || data.mensagem || "Falha ao consultar CVE.", "error");
        return;
      }

      this.cveAtualConsultada = data;
      document.getElementById("cve-res-id").textContent = data.id;
      document.getElementById("cve-res-cvss").textContent = `CVSS: ${data.cvss || "N/A"}`;
      document.getElementById("cve-res-descricao").textContent = data.descricao || data.descricao_en || "Sem descrição.";

      const badgeSev = document.getElementById("cve-res-severidade");
      const cvssNum = parseFloat(data.cvss);
      if (cvssNum >= 9.0) {
        badgeSev.textContent = "CRÍTICO";
        badgeSev.className = "badge badge-critico";
      } else if (cvssNum >= 7.0) {
        badgeSev.textContent = "ALTO";
        badgeSev.className = "badge badge-alto";
      } else if (cvssNum >= 4.0) {
        badgeSev.textContent = "MÉDIO";
        badgeSev.className = "badge badge-medio";
      } else {
        badgeSev.textContent = "BAIXO";
        badgeSev.className = "badge badge-baixo";
      }

      document.getElementById("cve-res-mitigacao").textContent =
        cvssNum >= 7.0
          ? "💡 Recomendação: Aplicar atualização corretiva com prioridade e isolar o host se exposto à Internet."
          : "💡 Recomendação: Agendar mitigação na próxima janela regular de manutenção.";

      card.style.display = "block";
    } catch (e) {
      this.mostrarToast("Falha ao consultar a API da NVD.", "error");
    }
  }

  async vincularCveAoAtivo() {
    if (!this.cveAtualConsultada) return;
    const idAtivo = document.getElementById("sel-ativo-vincular-cve").value;

    if (!idAtivo) {
      this.mostrarToast("Selecione o ativo ao qual vincular esta vulnerabilidade!", "error");
      return;
    }

    try {
      const res = await this.apiFetch(`/api/ativos/${encodeURIComponent(idAtivo)}/cves`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve: this.cveAtualConsultada.id }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast(`${this.cveAtualConsultada.id} associada ao Ativo ${idAtivo}!`, "success");
        await this.carregarDados();
      } else {
        this.mostrarToast(data.mensagem || "Esta CVE já está vinculada a este equipamento.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao vincular CVE.", "error");
    }
  }

  async carregarUsuarios() {
    try {
      const res = await this.apiFetch("/api/usuarios");
      const data = await res.json();

      if (!res.ok) {
        this.mostrarToast(data.mensagem || "Sem permissão para listar usuários.", "error");
        return;
      }

      const tbody = document.getElementById("tbody-usuarios");
      tbody.textContent = "";

      if (!data.usuarios) return;

      Object.entries(data.usuarios).forEach(([login, info]) => {
        const tr = document.createElement("tr");

        const tdLogin = document.createElement("td");
        const strongLogin = document.createElement("strong");
        strongLogin.textContent = login;
        tdLogin.appendChild(strongLogin);
        tr.appendChild(tdLogin);

        const tdNome = document.createElement("td");
        tdNome.textContent = info.nome || login;
        tr.appendChild(tdNome);

        const tdRole = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `badge ${info.role === "admin" ? "badge-success" : "badge-role"}`;
        badge.textContent = String(info.role || "user").toUpperCase();
        tdRole.appendChild(badge);
        tr.appendChild(tdRole);

        const tdAcoes = document.createElement("td");
        if (login !== "admin") {
          const btnExcluir = document.createElement("button");
          btnExcluir.type = "button";
          btnExcluir.className = "btn btn-danger btn-sm";
          btnExcluir.textContent = "Excluir 🗑️";
          btnExcluir.addEventListener("click", () => this.excluirUsuario(login));
          tdAcoes.appendChild(btnExcluir);
        } else {
          const smallPadrao = document.createElement("small");
          smallPadrao.style.color = "var(--text-muted)";
          smallPadrao.textContent = "Padrão";
          tdAcoes.appendChild(smallPadrao);
        }
        tr.appendChild(tdAcoes);

        tbody.appendChild(tr);
      });
    } catch (e) {
      this.mostrarToast("Erro ao carregar lista de usuários.", "error");
    }
  }

  async cadastrarUsuario() {
    const usuario = document.getElementById("novo-user-login").value.trim().toLowerCase();
    const nome = document.getElementById("novo-user-nome").value.trim();
    const senha = document.getElementById("novo-user-senha").value;
    const role = document.getElementById("novo-user-role").value;

    if (!usuario || !nome || !senha) {
      this.mostrarToast("Preencha todos os campos do usuário!", "error");
      return;
    }

    try {
      const res = await this.apiFetch("/api/usuarios", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usuario, nome, senha, role }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast(data.mensagem || `Usuário '${usuario}' cadastrado!`, "success");
        document.getElementById("form-novo-usuario").reset();
        this.carregarUsuarios();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao cadastrar usuário.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro de comunicação com o servidor.", "error");
    }
  }

  async excluirUsuario(login) {
    if (!confirm(`Remover o acesso do usuário '${login}'?`)) return;

    try {
      const res = await this.apiFetch(`/api/usuarios/${encodeURIComponent(login)}`, { method: "DELETE" });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast(`Usuário '${login}' excluído!`, "info");
        this.carregarUsuarios();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao remover usuário.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao remover usuário.", "error");
    }
  }

  abrirModalSenha() {
    document.getElementById("form-alterar-senha").reset();
    document.getElementById("modal-senha").style.display = "flex";
  }

  fecharModalSenha() {
    document.getElementById("modal-senha").style.display = "none";
  }

  async confirmarAlteracaoSenha() {
    const atual = document.getElementById("senha-atual").value;
    const nova = document.getElementById("senha-nova").value;
    const confirma = document.getElementById("senha-confirma").value;

    if (nova !== confirma) {
      this.mostrarToast("A nova senha e a confirmação não coincidem!", "error");
      return;
    }

    try {
      const res = await this.apiFetch("/api/alterar-senha", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          senha_atual: atual,
          nova_senha: nova,
        }),
      });
      const data = await res.json();

      if (res.ok && data.sucesso) {
        this.mostrarToast("Senha alterada com sucesso!", "success");
        document.getElementById("form-alterar-senha").reset();
        this.fecharModalSenha();
      } else {
        this.mostrarToast(data.mensagem || "Erro ao alterar senha.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao alterar senha.", "error");
    }
  }

  abrirModalMatrizes() {
    if (!this.dadosRisco || !this.dadosRisco.sucesso) {
      this.mostrarToast("Nenhum dado matemático disponível no momento.", "info");
      return;
    }

    const modal = document.getElementById("modal-matrizes");
    modal.style.display = "flex";

    const mContainer = document.getElementById("matriz-M-container");
    const m = this.dadosRisco.matriz_M || [];
    const v = this.dadosRisco.vetor_v || [];
    const cves = this.dadosRisco.vulnerabilidades_cves || [];
    const ids = this.dadosRisco.equipamentos_ids || [];

    let txtM =
      "Vulnerabilidades (colunas):\n" +
      cves.map((c, idx) => `  v[${idx}] = ${c} (CVSS: ${v[idx]})`).join("\n") +
      "\n\n";
    txtM += "Matriz de Incidência M (" + ids.length + "x" + cves.length + "):\n";
    m.forEach((row, idx) => {
      txtM += `  Equipamento ID ${ids[idx]}: [ ` + row.join(", ") + " ]\n";
    });
    mContainer.textContent = txtM;

    const aContainer = document.getElementById("matriz-A-container");
    const a = this.dadosRisco.matriz_A || [];
    const ia = this.dadosRisco.matriz_I_A || [];

    let txtA = "Matriz de Dependências A (" + ids.length + "x" + ids.length + ") com A_ii = 0:\n";
    a.forEach((row, idx) => {
      txtA += `  ID ${ids[idx]}: [ ` + row.map((val) => val.toFixed(2)).join(", ") + " ]\n";
    });
    txtA += "\nMatriz do Sistema (I - A):\n";
    ia.forEach((row, idx) => {
      txtA += `  ID ${ids[idx]}: [ ` + row.map((val) => (val >= 0 ? " " : "") + val.toFixed(2)).join(", ") + " ]\n";
    });
    txtA += `\nDiagnóstico de Invertibilidade:\n`;
    txtA += `  - Determinante det(I - A) = ${Number(this.dadosRisco.determinante).toFixed(6)}\n`;
    txtA += `  - Invertível: ${this.dadosRisco.invertivel ? "SIM (Solução única garantida)" : "NÃO (Matriz Singular)"}\n`;
    aContainer.textContent = txtA;

    const solContainer = document.getElementById("vetores-solucao-container");
    const b = this.dadosRisco.risco_proprio_b || [];
    const x = this.dadosRisco.risco_efetivo_x || [];

    let txtSol = "Equação Linear: (I - A) x = b  <=>  x = b + A x\n\n";
    ids.forEach((id, idx) => {
      txtSol += `Equipamento ID ${id}:\n`;
      txtSol += `  • Risco Próprio (b): ${Number(b[idx]).toFixed(4)}\n`;
      txtSol += `  • Risco Efetivo (x): ${Number(x[idx]).toFixed(4)}  (Próprio + Risco Herdado via Matriz A)\n\n`;
    });
    solContainer.textContent = txtSol;
  }

  fecharModalMatrizes() {
    document.getElementById("modal-matrizes").style.display = "none";
  }

  mostrarToast(mensagem, tipo = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${tipo}`;

    const icones = { success: "✅", error: "❌", info: "ℹ️" };
    const spanIcone = document.createElement("span");
    spanIcone.textContent = icones[tipo] || "ℹ️";
    const spanTexto = document.createElement("span");
    spanTexto.textContent = String(mensagem || "");

    toast.appendChild(spanIcone);
    toast.appendChild(document.createTextNode(" "));
    toast.appendChild(spanTexto);

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

const app = new InventarioApp();
