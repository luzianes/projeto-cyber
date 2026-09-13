from datetime import date, time, timedelta

from django.contrib.auth.models import User
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from .models import Cafe, UserCliente, ReservaCafe


# Em teste, usa o storage de estáticos simples (o padrão de produção é o
# ManifestStaticFilesStorage do WhiteNoise, que exigiria `collectstatic`).
@override_settings(STORAGES={
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
})
class ControleAcessoTests(TestCase):
    """Testes de regressão dos controles de acesso (autorização/autenticação).

    Cobrem os furos corrigidos:
      - IDOR em editar_reserva / excluir_reserva (autorização por objeto);
      - @login_required faltando em editar_cadastro_cafe e enviar_email;
      - enumeração de usuários no login (mensagem genérica).
    """

    def setUp(self):
        self.client = Client()

        # Dona da reserva
        self.alice = User.objects.create_user(
            'alice', password='senhaAlice123', email='alice@example.com')
        self.uc_alice = UserCliente.objects.create(
            user=self.alice, nome_completo='Alice', email='alice@example.com')

        # "Atacante": outro usuário legítimo, mas não dono da reserva
        self.bob = User.objects.create_user(
            'bob', password='senhaBob12345', email='bob@example.com')
        self.uc_bob = UserCliente.objects.create(
            user=self.bob, nome_completo='Bob', email='bob@example.com')

        self.cafe = Cafe.objects.create(
            nome_cafeteria='Cafe X', cnpj='11111111111111',
            whatsapp='5581911111111', email='x@example.com',
            empresario=self.uc_alice)

        self.reserva = ReservaCafe.objects.create(
            cafe=self.cafe, cliente=self.uc_alice, nome_cliente='Alice',
            data_reserva=date.today() + timedelta(days=5),
            horario_reserva=time(10, 0), numero_de_pessoas=2,
            observacao='mesa da janela')

    # ---- IDOR ---------------------------------------------------------------
    def test_editar_reserva_de_outro_usuario_e_bloqueado(self):
        self.client.login(username='bob', password='senhaBob12345')
        resp = self.client.get(reverse('editar_reserva', args=[self.reserva.id]))
        self.assertEqual(resp.status_code, 404)

    def test_excluir_reserva_de_outro_usuario_e_bloqueado(self):
        self.client.login(username='bob', password='senhaBob12345')
        resp = self.client.post(reverse('excluir_reserva', args=[self.reserva.id]))
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(ReservaCafe.objects.filter(id=self.reserva.id).exists())

    def test_dono_edita_e_exclui_a_propria_reserva(self):
        self.client.login(username='alice', password='senhaAlice123')
        self.assertEqual(
            self.client.get(reverse('editar_reserva', args=[self.reserva.id])).status_code,
            200)
        resp = self.client.post(reverse('excluir_reserva', args=[self.reserva.id]))
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(ReservaCafe.objects.filter(id=self.reserva.id).exists())

    # ---- @login_required faltando ------------------------------------------
    def test_editar_cadastro_cafe_exige_login(self):
        resp = self.client.get(reverse('editar_cadastro', args=[self.cafe.id]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.url)

    def test_enviar_email_exige_login(self):
        resp = self.client.get(reverse('enviar-email', args=[self.cafe.id]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.url)

    # ---- Enumeração de usuários no login ------------------------------------
    def test_login_nao_diferencia_email_inexistente_de_senha_errada(self):
        r_email = self.client.post(
            reverse('login'),
            {'email': 'naoexiste@example.com', 'password': 'x'})
        r_senha = self.client.post(
            reverse('login'),
            {'email': 'alice@example.com', 'password': 'errada'})
        # Mesma mensagem genérica nos dois casos, sem revelar o que existe.
        self.assertContains(r_email, 'inválidos')
        self.assertContains(r_senha, 'inválidos')
        self.assertNotContains(r_email, 'não encontrado')
        self.assertNotContains(r_email, 'Usuário')
