from io import StringIO

from cryptography.fernet import Fernet
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, override_settings

from .models import Avaliacao, Cafe, ReservaCafe


@override_settings(
    FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
)
class SeedIfEmptyTests(TestCase):
    def seed(self):
        call_command("seed_fake_data", if_empty=True, stdout=StringIO())

    def test_fresh_database_is_populated_and_changes_survive_second_start(self):
        self.seed()
        self.assertEqual(User.objects.count(), 30)
        self.assertEqual(Cafe.objects.count(), 6)
        self.assertEqual(ReservaCafe.objects.count(), 4)
        self.assertEqual(ReservaCafe.objects.first().nome_cliente, "Ana Bezerra")

        user = User.objects.get(username="maria_julia")
        user.set_password("senha-alterada")
        user.save()
        cafe = Cafe.objects.first()
        cafe.nome_cafeteria = "Nome editado pelo usuario"
        cafe.save()
        review = Avaliacao.objects.first()
        review.comentario = "Avaliacao editada pelo usuario"
        review.save()
        reservation_ids = list(ReservaCafe.objects.values_list("pk", flat=True))

        self.seed()

        user.refresh_from_db()
        cafe.refresh_from_db()
        review.refresh_from_db()
        self.assertTrue(user.check_password("senha-alterada"))
        self.assertEqual(cafe.nome_cafeteria, "Nome editado pelo usuario")
        self.assertEqual(review.comentario, "Avaliacao editada pelo usuario")
        self.assertEqual(list(ReservaCafe.objects.values_list("pk", flat=True)), reservation_ids)
        self.assertEqual(User.objects.count(), 30)

    @override_settings(FIELD_ENCRYPTION_KEY="")
    def test_existing_user_prevents_seeding_even_without_encryption_key(self):
        User.objects.create_user("usuario_existente")
        self.seed()
        self.assertEqual(User.objects.count(), 1)
        self.assertFalse(Cafe.objects.exists())

    def test_existing_cafe_without_users_prevents_seeding(self):
        Cafe.objects.create(nome_cafeteria="Minha cafeteria", cnpj="12345678901234")
        self.seed()
        self.assertFalse(User.objects.exists())
        self.assertEqual(Cafe.objects.count(), 1)
