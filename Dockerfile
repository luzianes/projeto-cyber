FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace/projeto

COPY projeto/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# O Compose monta o repositorio para usar o codigo atual e persistir projeto.env.
CMD ["python", "../docker/init_db.py"]
