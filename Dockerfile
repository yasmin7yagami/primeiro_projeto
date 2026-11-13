# Imagem base oficial enxuta (Python 3.11 slim)
FROM python:3.11-slim

# Evita a geração de arquivos .pyc e ativa saída sem buffer
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Criação de usuário sem privilégios para segurança operacional (Requisito S4_16)
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Instalação do curl para healthchecks e diagnósticos de rede
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Aproveitamento do cache de camadas copiando dependências primeiro
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cópia do código-fonte da aplicação
COPY . .

# Ajusta permissões dos arquivos para o usuário não-root
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Verificação contínua de Saúde (HEALTHCHECK) para garantir permanência 24h (Requisito 3)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

# Comando padrão de inicialização: executa o servidor daemon contínuo 24h
CMD ["python", "app_server.py"]
