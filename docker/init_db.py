"""Prepara o banco local e as chaves de desenvolvimento pelo Docker Compose."""

import os
from pathlib import Path
import secrets
import sys

from cryptography.fernet import Fernet
from dotenv import load_dotenv, set_key


ROOT = Path(__file__).resolve().parent.parent


def prepare_local_env():
    env_path = ROOT / "projeto.env"
    load_dotenv(ROOT / ".env")
    load_dotenv(env_path)

    if not env_path.exists():
        # O host acessa a porta publicada; o db-init usa db:5432 na rede Docker.
        defaults = {
            "TARGET_ENV": "dev",
            "DEBUG": "1",
            "ALLOWED_HOSTS": "127.0.0.1 localhost",
            "USE_POSTGRES": "1",
            "DBHOST": "localhost",
            "DBPORT": os.environ["DB_EXTERNAL_PORT"],
            "DBNAME": os.environ["DBNAME"],
            "DBUSER": os.environ["DBUSER"],
            "DBPASS": os.environ["DBPASS"],
            "DBSSLMODE": "disable",
            "EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend",
        }
        env_path.touch(mode=0o600, exist_ok=False)
        for name, value in defaults.items():
            set_key(env_path, name, value)
        print("projeto.env criado para desenvolvimento local.")

    if not os.getenv("SECRET_KEY") or os.getenv("SECRET_KEY") == "troque-por-uma-chave-aleatoria-local":
        key = secrets.token_urlsafe(48)
        set_key(env_path, "SECRET_KEY", key)
        os.environ["SECRET_KEY"] = key

    if not os.getenv("FIELD_ENCRYPTION_KEY"):
        key = Fernet.generate_key().decode()
        set_key(env_path, "FIELD_ENCRYPTION_KEY", key)
        os.environ["FIELD_ENCRYPTION_KEY"] = key

    # Falha antes da carga caso uma chave existente esteja invalida.
    Fernet(os.environ["FIELD_ENCRYPTION_KEY"].encode())


def main():
    # Arquivos gerados no volume devem pertencer ao usuario do repositorio.
    if os.geteuid() == 0:
        owner = ROOT.stat()
        os.setgroups([])
        os.setgid(owner.st_gid)
        os.setuid(owner.st_uid)

    prepare_local_env()
    sys.path.insert(0, str(ROOT / "projeto"))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "g3.settings")

    import django
    from django.core.management import call_command

    django.setup()
    call_command("migrate", interactive=False)
    call_command("seed_fake_data", if_empty=True)
    # Gera projeto/staticfiles/ (nao versionado) a partir do zero em qualquer
    # maquina/deploy novo, evitando o 500 "Missing staticfiles manifest entry".
    call_command("collectstatic", interactive=False, verbosity=0)
    print("Banco pronto para uso.")


if __name__ == "__main__":
    main()
