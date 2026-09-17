from datetime import date, time, timedelta
from unittest.mock import patch
from urllib.parse import urlparse

from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from .models import Cafe, UserCliente, ReservaCafe


# Em teste, usa o storage de estáticos simples (o padrão de produção é o
# ManifestStaticFilesStorage do WhiteNoise, que exigiria `collectstatic`).
@override_settings(
    ALLOWED_HOSTS=["testserver"],
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="no-reply@apontecafes.local",
    STORAGES={
        "default": {
            "BACKEND": "django.core.files.storage.FileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    },
)
class ControleAcessoTests(TestCase):
    """Testes de regressão dos controles de acesso (autorização/autenticação).

    Cobrem os furos corrigidos:
      - IDOR em editar_reserva / excluir_reserva (autorização por objeto);
      - @login_required faltando em editar_cadastro_cafe e enviar_email;
      - enumeração de usuários no login (mensagem genérica).
    """

    def setUp(self):
        self.client = Client()
        mail.outbox = []

        # Testes de login/cadastro não devem depender da API real do
        # reCAPTCHA (rede + chave de teste); a view só usa o resultado.
        patcher_recaptcha = patch('apps.views.recaptcha_valido', return_value=True)
        patcher_recaptcha.start()
        self.addCleanup(patcher_recaptcha.stop)

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
        self.assertContains(r_email, 'Usuario ou senha invalidos.')
        self.assertContains(r_senha, 'Usuario ou senha invalidos.')
        self.assertNotContains(r_email, 'não encontrado')
        self.assertNotContains(r_email, 'Usuário')

    # ---- Cadastro ----------------------------------------------------------
    def test_cadastro_nao_permite_email_repetido(self):
        resp = self.client.post(reverse('UserCadastro'), {
            'username': 'novo_usuario',
            'name': 'Novo Usuario',
            'email': 'ALICE@example.com',
            'password': 'Senha@123',
            'confirm_password': 'Senha@123',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'E-mail ja cadastrado.')
        self.assertFalse(User.objects.filter(username='novo_usuario').exists())

    def test_cadastro_exige_senha_com_regras_minimas(self):
        casos = [
            ('senha_curta', 'Ab1!xyz', '8'),
            ('senha_sem_maiuscula', 'senha@123', 'letra maiuscula'),
            ('senha_sem_minuscula', 'SENHA@123', 'letra minuscula'),
            ('senha_sem_numero', 'Senha@abc', 'numero'),
            ('senha_sem_especial', 'Senha123', 'caractere especial'),
        ]

        for username, password, expected_message in casos:
            with self.subTest(username=username):
                resp = self.client.post(reverse('UserCadastro'), {
                    'username': username,
                    'name': 'Usuario Teste',
                    'email': f'{username}@example.com',
                    'password': password,
                    'confirm_password': password,
                })

                self.assertEqual(resp.status_code, 200)
                self.assertContains(resp, expected_message)
                self.assertFalse(User.objects.filter(username=username).exists())

    # ---- Esqueci minha senha ----------------------------------------------
    def test_esqueci_senha_tem_mesmo_comportamento_para_conta_existente_ou_nao(self):
        resp_existente = self.client.post(
            reverse('esqueci_senha'),
            {'usuario_ou_email': 'alice@example.com'},
        )
        self.assertRedirects(resp_existente, reverse('senha_redefinicao_enviada'))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('Caso tenha solicitado recuperacao de senha', mail.outbox[0].body)

        mail.outbox = []
        resp_inexistente = self.client.post(
            reverse('esqueci_senha'),
            {'usuario_ou_email': 'naoexiste@example.com'},
        )
        self.assertRedirects(resp_inexistente, reverse('senha_redefinicao_enviada'))
        self.assertEqual(len(mail.outbox), 0)

        pagina = self.client.get(reverse('senha_redefinicao_enviada'))
        self.assertContains(pagina, 'Se os dados informados corresponderem a uma conta')

    def test_esqueci_senha_aceita_username(self):
        resp = self.client.post(
            reverse('esqueci_senha'),
            {'usuario_ou_email': 'alice'},
        )

        self.assertRedirects(resp, reverse('senha_redefinicao_enviada'))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('alice@example.com', mail.outbox[0].to)

    def test_link_de_redefinicao_altera_senha(self):
        self.client.post(
            reverse('esqueci_senha'),
            {'usuario_ou_email': 'alice@example.com'},
        )
        reset_url = next(
            line.strip()
            for line in mail.outbox[0].body.splitlines()
            if line.startswith('http')
        )
        reset_path = urlparse(reset_url).path

        resp_get = self.client.get(reset_path)
        self.assertEqual(resp_get.status_code, 200)

        resp_post = self.client.post(reset_path, {
            'password': 'NovaSenha@123',
            'confirm_password': 'NovaSenha@123',
        })
        self.assertRedirects(resp_post, reverse('senha_redefinida_sucesso'))

        self.alice.refresh_from_db()
        self.assertTrue(self.alice.check_password('NovaSenha@123'))
