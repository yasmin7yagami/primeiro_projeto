/**
 * UFU — CIBERSEGURANÇA | Trabalho 02 (Sprints 3 a 5)
 * Controlador Frontend Web SPA (Vanilla JavaScript)
 */

class InventarioApp {
  constructor() {
    this.usuarioLogado = null;
    this.ativos = [];
    this.dadosRisco = null;
    this.cveAtualConsultada = null;

    // Inicialização ao carregar a página
    window.addEventListener("DOMContentLoaded", () => this.inicializar());
  }

  inicializar() {
    const sessaoSalva = localStorage.getItem("sessao_ciberseguranca");
    if (sessaoSalva) {
      try {
        this.usuarioLogado = JSON.parse(sessaoSalva);
        this.exibirAplicacao();
      } catch (e) {
        localStorage.removeItem("sessao_ciberseguranca");
        this.exibirLogin();
      }
    } else {
      this.exibirLogin();
    }
  }

  // =========================================================================
  // AUTENTICAÇÃO E SESSÃO
  // =========================================================================
  async efetuarLogin() {
    const usuario = document.getElementById("login-usuario").value.trim();
    const senha = document.getElementById("login-senha").value;

    if (!usuario || !senha) {
      this.mostrarToast("Informe usuário e senha!", "error");
      return;
    }

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usuario, senha }),
      });
      const data = await res.json();

      if (data.sucesso) {
        this.usuarioLogado = data.usuario;
        localStorage.setItem("sessao_ciberseguranca", JSON.stringify(this.usuarioLogado));
        this.mostrarToast(`Bem-vinda, ${this.usuarioLogado.nome}!`, "success");
        this.exibirAplicacao();
      } else {
        this.mostrarToast(data.mensagem || "Credenciais incorretas!", "error");
      }
    } catch (err) {
      this.mostrarToast("Falha na comunicação com o servidor.", "error");
    }
  }

  efetuarLogout() {
    localStorage.removeItem("sessao_ciberseguranca");
    this.usuarioLogado = null;
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

    // Atualiza cabeçalho com dados da sessão
    document.getElementById("header-user-name").textContent = `👤 ${this.usuarioLogado.nome}`;
    const badgeRole = document.getElementById("header-user-role");
    badgeRole.textContent = this.usuarioLogado.role.toUpperCase();
    badgeRole.className = `badge ${this.usuarioLogado.role === "admin" ? "badge-success" : "badge-role"}`;

    // Exibe aba de gestão de usuários apenas se for admin
    const tabAdmin = document.getElementById("tab-btn-usuarios");
    tabAdmin.style.display = this.usuarioLogado.role === "admin" ? "inline-block" : "none";

    this.carregarDados();
  }

  // =========================================================================
  // NAVEGAÇÃO POR ABAS
  // =========================================================================
  mudarAba(nomeAba) {
    document.querySelectorAll(".nav-tab").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

    const btnTab = Array.from(document.querySelectorAll(".nav-tab")).find(b =>
      b.getAttribute("onclick").includes(`'${nomeAba}'`)
    );
    if (btnTab) btnTab.classList.add("active");

    const targetPane = document.getElementById(`aba-${nomeAba}`);
    if (targetPane) targetPane.classList.add("active");

    if (nomeAba === "usuarios" && this.usuarioLogado.role === "admin") {
      this.carregarUsuarios();
    }
  }

  // =========================================================================
  // CARREGAMENTO DE DADOS (API REST)
  // =========================================================================
  async carregarDados() {
    try {
      // 1. Healthcheck / Uptime
      const resHealth = await fetch("/api/health");
      if (resHealth.ok) {
        const health = await resHealth.json();
        const horas = health.uptime_horas || 0;
        document.getElementById("metric-uptime").textContent = `${horas}h online`;
      }

      // 2. Ativos
      const resAtivos = await fetch("/api/ativos");
      const dataAtivos = await resAtivos.json();
      this.ativos = dataAtivos.ativos || [];
      document.getElementById("metric-total-ativos").textContent = this.ativos.length;

      // 3. Análise de Risco (Álgebra Linear - Requisito 4)
      const resRisco = await fetch("/api/risco");
      this.dadosRisco = await resRisco.json();

      if (this.dadosRisco.sucesso) {
        document.getElementById("metric-invertivel").textContent = this.dadosRisco.invertivel ? "Sim ✅" : "Não ❌";
        document.getElementById("metric-invertivel").className = `metric-value ${this.dadosRisco.invertivel ? "text-success" : "text-danger"}`;
        document.getElementById("metric-det-sub").textContent = `det(I - A) = ${this.dadosRisco.determinante.toFixed(4)}`;
        document.getElementById("metric-total-cves").textContent = `${this.dadosRisco.vulnerabilidades_cves.length} CVEs`;
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
    tbody.innerHTML = "";

    if (!this.ativos || this.ativos.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">Nenhum ativo cadastrado no momento.</td></tr>`;
      return;
    }

    // Mapa de riscos calculados pela Álgebra Linear
    const mapaRisco = {};
    if (this.dadosRisco && this.dadosRisco.tabela) {
      this.dadosRisco.tabela.forEach(item => {
        mapaRisco[item.id] = {
          risco_proprio: item.risco_proprio,
          risco_efetivo: item.risco_efetivo,
          fator_exposicao: item.fator_exposicao,
        };
      });
    }

    this.ativos.forEach(ativo => {
      const id = ativo.id_ativo || ativo.id;
      const risco = mapaRisco[id] || { risco_proprio: 0, risco_efetivo: 0, fator_exposicao: 1.0 };

      const vuls = ativo.vulnerabilidades || [];
      const vulsHtml = vuls.length > 0
        ? vuls.map(cve => `<span class="badge badge-cvss" style="margin: 2px;">${cve}</span>`).join(" ")
        : '<span style="color: var(--text-muted);">Nenhuma</span>';

      const deps = ativo.dependencias || {};
      const depsEntries = Object.entries(deps);
      const depsHtml = depsEntries.length > 0
        ? depsEntries.map(([targetId, peso]) => `<span class="chip" style="font-size: 11px;">ID ${targetId}: <strong>${Math.round(peso * 100)}%</strong></span>`).join(" ")
        : '<span style="color: var(--text-muted); font-size: 12px;">Nenhuma</span>';

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${id}</strong></td>
        <td>${ativo.hostname}</td>
        <td><span class="badge badge-role">${ativo.tipo}</span></td>
        <td>${ativo.responsavel}</td>
        <td>${ativo.localizacao}</td>
        <td>${vulsHtml}</td>
        <td>${risco.fator_exposicao}x</td>
        <td class="risco-proprio">${risco.risco_proprio.toFixed(2)}</td>
        <td class="risco-efetivo">${risco.risco_efetivo.toFixed(2)}</td>
        <td>${depsHtml}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  filtrarTabela() {
    const termo = document.getElementById("filtro-busca").value.toLowerCase().trim();
    const linhas = document.querySelectorAll("#tbody-inventario tr");

    linhas.forEach(linha => {
      const texto = linha.textContent.toLowerCase();
      linha.style.display = texto.includes(termo) ? "" : "none";
    });
  }

  limparFiltro() {
    document.getElementById("filtro-busca").value = "";
    this.filtrarTabela();
  }

  // =========================================================================
  // CAMPOS DINÂMICOS CONFORME O TIPO POO
  // =========================================================================
  atualizarCamposDinamicos(prefixo) {
    const tipo = document.getElementById(`${prefixo}-tipo`).value;
    const label1 = document.getElementById(`${prefixo}-label-dinamico-1`);
    const input1 = document.getElementById(`${prefixo}-input-dinamico-1`);
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

  // =========================================================================
  // CRUD DE ATIVOS
  // =========================================================================
  async salvarNovoAtivo() {
    const id_ativo = parseInt(document.getElementById("cad-id").value);
    const hostname = document.getElementById("cad-hostname").value.trim();
    const responsavel = document.getElementById("cad-responsavel").value.trim();
    const localizacao = document.getElementById("cad-localizacao").value.trim();
    const tipo = document.getElementById("cad-tipo").value;

    const payload = { id_ativo, hostname, responsavel, localizacao, tipo };

    if (tipo === "Servidores") {
      payload.sistema_operacional = document.getElementById("cad-input-dinamico-1").value.trim();
      payload.funcao = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Roteadores/Switches") {
      payload.qtd_portas = parseInt(document.getElementById("cad-input-dinamico-1").value) || 24;
      payload.camada = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Computadores") {
      payload.sistema_operacional = document.getElementById("cad-input-dinamico-1").value.trim();
      payload.departamento = document.getElementById("cad-input-dinamico-2").value.trim();
    } else if (tipo === "Impressoras") {
      payload.tipo_impressao = document.getElementById("cad-input-dinamico-1").value.trim();
    }

    try {
      const res = await fetch("/api/ativos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();

      if (data.sucesso) {
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

  atualizarSelectsAtivos() {
    const selectGerenciar = document.getElementById("sel-ativo-gerenciar");
    const selectVincular = document.getElementById("sel-ativo-vincular-cve");
    const selectDepAlvo = document.getElementById("sel-dependencia-alvo");

    selectGerenciar.innerHTML = '<option value="">-- Escolha um ativo da lista --</option>';
    selectVincular.innerHTML = '<option value="">-- Selecione o ativo --</option>';
    selectDepAlvo.innerHTML = '<option value="">-- Selecione o equipamento --</option>';

    this.ativos.forEach(a => {
      const id = a.id_ativo || a.id;
      const optText = `[ID ${id}] ${a.hostname} (${a.tipo})`;

      selectGerenciar.innerHTML += `<option value="${id}">${optText}</option>`;
      selectVincular.innerHTML += `<option value="${id}">${optText}</option>`;
      selectDepAlvo.innerHTML += `<option value="${id}">${optText}</option>`;
    });
  }

  carregarDadosParaEdicao() {
    const idSelecionado = document.getElementById("sel-ativo-gerenciar").value;
    const box = document.getElementById("box-edicao-ativo");

    if (!idSelecionado) {
      box.style.display = "none";
      return;
    }

    const ativo = this.ativos.find(a => (a.id_ativo || a.id) == idSelecionado);
    if (!ativo) return;

    box.style.display = "block";
    document.getElementById("edit-id").value = idSelecionado;
    document.getElementById("edit-hostname").value = ativo.hostname;
    document.getElementById("edit-responsavel").value = ativo.responsavel;
    document.getElementById("edit-localizacao").value = ativo.localizacao;
    document.getElementById("edit-tipo").value = ativo.tipo;

    this.renderizarChipsDependencias(ativo);
  }

  renderizarChipsDependencias(ativo) {
    const container = document.getElementById("lista-dependencias-ativo");
    container.innerHTML = "";

    const deps = ativo.dependencias || {};
    const entries = Object.entries(deps);

    if (entries.length === 0) {
      container.innerHTML = `<span style="color: var(--text-muted); font-size: 12px;">Nenhuma dependência cadastrada para este ativo.</span>`;
      return;
    }

    entries.forEach(([targetId, peso]) => {
      const targetAtivo = this.ativos.find(a => (a.id_ativo || a.id) == targetId);
      const targetName = targetAtivo ? targetAtivo.hostname : `ID ${targetId}`;

      const chip = document.createElement("div");
      chip.className = "chip";
      chip.innerHTML = `
        <span>Depende de <strong>${targetName}</strong>: ${(peso * 100).toFixed(0)}% do risco</span>
        <span class="chip-remove" onclick="app.removerDependencia(${targetId})">×</span>
      `;
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

    if (idOrigem == idAlvo) {
      this.mostrarToast("Um equipamento não pode depender de si mesmo (A_ii = 0)!", "error");
      return;
    }

    try {
      const res = await fetch(`/api/ativos/${idOrigem}/dependencias`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_alvo: parseInt(idAlvo), peso }),
      });
      const data = await res.json();

      if (data.sucesso) {
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
      const res = await fetch(`/api/ativos/${idOrigem}/dependencias/${idAlvo}`, { method: "DELETE" });
      const data = await res.json();
      if (data.sucesso) {
        this.mostrarToast("Dependência removida!", "info");
        await this.carregarDados();
        this.carregarDadosParaEdicao();
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
      const res = await fetch(`/api/ativos/${id_ativo}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname, responsavel, localizacao, tipo }),
      });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast("Ativo atualizado com sucesso!", "success");
        await this.carregarDados();
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
      const res = await fetch(`/api/ativos/${id}`, { method: "DELETE" });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast(`Ativo ID ${id} excluído com sucesso!`, "success");
        document.getElementById("box-edicao-ativo").style.display = "none";
        await this.carregarDados();
      } else {
        this.mostrarToast(data.mensagem || "Falha ao excluir ativo.", "error");
      }
    } catch (e) {
      this.mostrarToast("Falha ao se comunicar com o servidor.", "error");
    }
  }

  // =========================================================================
  // VULNERABILIDADES & NIST/NVD
  // =========================================================================
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
      const res = await fetch(`/api/cve/consultar?codigo=${encodeURIComponent(codigo)}`);
      const data = await res.json();

      if (data.erro) {
        this.mostrarToast(data.erro, "error");
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

      document.getElementById("cve-res-mitigacao").textContent = cvssNum >= 7.0
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
      const res = await fetch(`/api/ativos/${idAtivo}/cves`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve: this.cveAtualConsultada.id }),
      });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast(`${this.cveAtualConsultada.id} associada ao Ativo ${idAtivo}!`, "success");
        await this.carregarDados();
      } else {
        this.mostrarToast(data.mensagem || "Esta CVE já está vinculada a este equipamento.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao vincular CVE.", "error");
    }
  }

  // =========================================================================
  // GESTÃO DE USUÁRIOS (ADMIN)
  // =========================================================================
  async carregarUsuarios() {
    try {
      const res = await fetch("/api/usuarios");
      const data = await res.json();

      const tbody = document.getElementById("tbody-usuarios");
      tbody.innerHTML = "";

      if (!data.usuarios) return;

      Object.entries(data.usuarios).forEach(([login, info]) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${login}</strong></td>
          <td>${info.nome || login}</td>
          <td><span class="badge ${info.role === "admin" ? "badge-success" : "badge-role"}">${info.role.toUpperCase()}</span></td>
          <td>
            ${login !== "admin" ? `<button class="btn btn-danger btn-sm" onclick="app.excluirUsuario('${login}')">Excluir 🗑️</button>` : '<small style="color: var(--text-muted);">Padrão</small>'}
          </td>
        `;
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
      const res = await fetch("/api/usuarios", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ usuario, nome, senha, role }),
      });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast(`Usuário '${usuario}' cadastrado!`, "success");
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
      const res = await fetch(`/api/usuarios/${login}`, { method: "DELETE" });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast(`Usuário '${login}' excluído!`, "info");
        this.carregarUsuarios();
      } else {
        this.mostrarToast(data.mensagem, "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao remover usuário.", "error");
    }
  }

  // =========================================================================
  // MODAL DE ALTERAÇÃO DE SENHA
  // =========================================================================
  abrirModalSenha() {
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
      const res = await fetch("/api/alterar-senha", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          login_id: this.usuarioLogado.login_id,
          senha_atual: atual,
          nova_senha: nova,
        }),
      });
      const data = await res.json();

      if (data.sucesso) {
        this.mostrarToast("Senha alterada com sucesso!", "success");
        this.fecharModalSenha();
      } else {
        this.mostrarToast(data.mensagem || "Senha atual incorreta.", "error");
      }
    } catch (e) {
      this.mostrarToast("Erro ao alterar senha.", "error");
    }
  }

  // =========================================================================
  // MODAL DE INSPEÇÃO MATEMÁTICA DAS MATRIZES (ÁLGEBRA LINEAR)
  // =========================================================================
  abrirModalMatrizes() {
    if (!this.dadosRisco || !this.dadosRisco.sucesso) {
      this.mostrarToast("Nenhum dado matemático disponível no momento.", "info");
      return;
    }

    const modal = document.getElementById("modal-matrizes");
    modal.style.display = "flex";

    // 1. Renderiza M e v
    const mContainer = document.getElementById("matriz-M-container");
    const m = this.dadosRisco.matriz_M || [];
    const v = this.dadosRisco.vetor_v || [];
    const cves = this.dadosRisco.vulnerabilidades_cves || [];
    const ids = this.dadosRisco.equipamentos_ids || [];

    let txtM = "Vulnerabilidades (colunas):\n" + cves.map((c, idx) => `  v[${idx}] = ${c} (CVSS: ${v[idx]})`).join("\n") + "\n\n";
    txtM += "Matriz de Incidência M (" + ids.length + "x" + cves.length + "):\n";
    m.forEach((row, idx) => {
      txtM += `  Equipamento ID ${ids[idx]}: [ ` + row.join(", ") + " ]\n";
    });
    mContainer.textContent = txtM;

    // 2. Renderiza A e (I - A)
    const aContainer = document.getElementById("matriz-A-container");
    const a = this.dadosRisco.matriz_A || [];
    const ia = this.dadosRisco.matriz_I_A || [];

    let txtA = "Matriz de Dependências A (" + ids.length + "x" + ids.length + ") com A_ii = 0:\n";
    a.forEach((row, idx) => {
      txtA += `  ID ${ids[idx]}: [ ` + row.map(val => val.toFixed(2)).join(", ") + " ]\n";
    });
    txtA += "\nMatriz do Sistema (I - A):\n";
    ia.forEach((row, idx) => {
      txtA += `  ID ${ids[idx]}: [ ` + row.map(val => (val >= 0 ? " " : "") + val.toFixed(2)).join(", ") + " ]\n";
    });
    txtA += `\nDiagnóstico de Invertibilidade:\n`;
    txtA += `  - Determinante det(I - A) = ${this.dadosRisco.determinante.toFixed(6)}\n`;
    txtA += `  - Invertível: ${this.dadosRisco.invertivel ? "SIM (Solução única garantida)" : "NÃO (Matriz Singular)"}\n`;
    aContainer.textContent = txtA;

    // 3. Vetores de Risco Próprio b e Risco Efetivo x
    const solContainer = document.getElementById("vetores-solucao-container");
    const b = this.dadosRisco.risco_proprio_b || [];
    const x = this.dadosRisco.risco_efetivo_x || [];

    let txtSol = "Equação Linear: (I - A) x = b  <=>  x = b + A x\n\n";
    ids.forEach((id, idx) => {
      txtSol += `Equipamento ID ${id}:\n`;
      txtSol += `  • Risco Próprio (b): ${b[idx].toFixed(4)}\n`;
      txtSol += `  • Risco Efetivo (x): ${x[idx].toFixed(4)}  (Próprio + Risco Herdado via Matriz A)\n\n`;
    });
    solContainer.textContent = txtSol;
  }

  fecharModalMatrizes() {
    document.getElementById("modal-matrizes").style.display = "none";
  }

  // =========================================================================
  // TOASTS DE NOTIFICAÇÃO
  // =========================================================================
  mostrarToast(mensagem, tipo = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${tipo}`;

    const icones = { success: "✅", error: "❌", info: "ℹ️" };
    toast.innerHTML = `<span>${icones[tipo] || "ℹ️"}</span> <span>${mensagem}</span>`;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Instância global
const app = new InventarioApp();
