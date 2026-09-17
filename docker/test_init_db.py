import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from dotenv import dotenv_values

import init_db


class LocalEnvTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        root_patch = patch.object(init_db, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        env_patch = patch.dict(os.environ, {
            "DBHOST": "db",
            "DBPORT": "5432",
            "DB_EXTERNAL_PORT": "55432",
            "DBNAME": "test_db",
            "DBUSER": "test_user",
            "DBPASS": "local password # with punctuation",
        }, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def test_fresh_checkout_creates_persistent_keys_and_host_connection(self):
        init_db.prepare_local_env()
        values = dotenv_values(self.root / "projeto.env")
        self.assertEqual(values["DBHOST"], "localhost")
        self.assertEqual(values["DBPORT"], "55432")
        self.assertEqual(values["DBPASS"], os.environ["DBPASS"])
        self.assertEqual(os.environ["DBHOST"], "db")
        self.assertEqual(os.environ["DBPORT"], "5432")
        self.assertGreaterEqual(len(values["SECRET_KEY"]), 48)
        fernet = Fernet(values["FIELD_ENCRYPTION_KEY"].encode())
        self.assertEqual(fernet.decrypt(fernet.encrypt(b"reserva")), b"reserva")
        before = (self.root / "projeto.env").read_bytes()
        init_db.prepare_local_env()
        self.assertEqual((self.root / "projeto.env").read_bytes(), before)

    def test_existing_configuration_and_keys_are_preserved(self):
        key = Fernet.generate_key().decode()
        content = f"SECRET_KEY=existing-secret\nFIELD_ENCRYPTION_KEY={key}\nGEMINI_API_KEY=local-test-value\n"
        (self.root / "projeto.env").write_text(content)
        init_db.prepare_local_env()
        self.assertEqual((self.root / "projeto.env").read_text(), content)
        self.assertEqual(os.environ["SECRET_KEY"], "existing-secret")
        self.assertEqual(os.environ["FIELD_ENCRYPTION_KEY"], key)

    def test_example_placeholders_are_replaced(self):
        (self.root / "projeto.env").write_text(
            "SECRET_KEY=troque-por-uma-chave-aleatoria-local\nFIELD_ENCRYPTION_KEY=\n"
        )
        init_db.prepare_local_env()
        values = dotenv_values(self.root / "projeto.env")
        self.assertNotEqual(values["SECRET_KEY"], "troque-por-uma-chave-aleatoria-local")
        Fernet(values["FIELD_ENCRYPTION_KEY"].encode())

    def test_invalid_existing_encryption_key_is_not_replaced(self):
        content = "SECRET_KEY=existing-secret\nFIELD_ENCRYPTION_KEY=invalid\n"
        (self.root / "projeto.env").write_text(content)
        with self.assertRaises(ValueError):
            init_db.prepare_local_env()
        self.assertEqual((self.root / "projeto.env").read_text(), content)
