# Imagem base oficial enxuta (Python 3.11 slim)
FROM python:3.11-slim

# Evita a geração de arquivos .pyc e ativa saída sem buffer
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Criação de usuário sem privilégios para segurança operacional (Requisito S4_16)
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Aproveitamento do cache de camadas copiando dependências primeiro
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cópia do código-fonte da aplicação
COPY . .

# Ajusta permissões dos arquivos para o usuário não-root
RUN chown -R appuser:appuser /app

USER appuser

# Comando padrão de inicialização (executa a suíte de testes e validação no container)
CMD ["python", "-m", "pytest", "tests/"]
