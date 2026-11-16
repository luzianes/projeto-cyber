import os
import tempfile
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from . import analise_eventos as ae
from .eventos import registrar_evento, silenciar_eventos
from .mensageria_cripto import cifrar, decifrar, gerar_chave
from .models import EventoSeguranca


class RegistroDeEventosTests(TestCase):
    def test_registra_e_preenche_categoria_e_sucesso(self):
        e = registrar_evento('login_falha', usuario='ana', ip='10.0.0.1', origem='teste')
        self.assertEqual(e.categoria, 'autenticacao')
        self.assertFalse(e.sucesso)
        self.assertEqual(EventoSeguranca.objects.count(), 1)

    def test_remove_segredos_dos_detalhes(self):
        e = registrar_evento('cifragem', detalhes={'chave': 'SEGREDO', 'texto': 'oi', 'blocos': 3})
        self.assertEqual(e.detalhes, {'blocos': 3})

    def test_nunca_levanta_excecao(self):
        with mock.patch('apps.models.EventoSeguranca.objects.create', side_effect=RuntimeError('boom')):
            self.assertIsNone(registrar_evento('login_falha'))

    def test_silenciar(self):
        with silenciar_eventos():
            self.assertIsNone(registrar_evento('login_falha'))
        self.assertEqual(EventoSeguranca.objects.count(), 0)


class CifraGeraEventosTests(TestCase):
    def test_cifrar_e_decifrar_registram_sem_vazar_conteudo(self):
        chave = gerar_chave()
        cifrado = cifrar('segredo da cafeteria', chave, usuario='ana', ip='10.0.0.2')
        self.assertEqual(decifrar(cifrado, chave, usuario='ana'), 'segredo da cafeteria')
        tipos = list(EventoSeguranca.objects.order_by('id').values_list('tipo', flat=True))
        self.assertEqual(tipos, ['cifragem', 'decifragem'])
        todo = ' '.join(str(e.detalhes) for e in EventoSeguranca.objects.all())
        self.assertNotIn('segredo', todo)
        self.assertNotIn(chave, todo)

    def test_chave_errada_gera_falha_decifragem(self):
        cifrado = cifrar('mensagem de teste', gerar_chave())
        # O padding pode "passar" por acaso com chave errada; tenta várias vezes.
        falhas = 0
        for _ in range(30):
            try:
                decifrar(cifrado, gerar_chave(), usuario='intruso')
            except Exception:
                falhas += 1
        self.assertGreater(falhas, 0)
        self.assertEqual(
            EventoSeguranca.objects.filter(tipo='falha_decifragem', usuario='intruso').count(), falhas)

    def test_ataque_silenciado_nao_polui_a_tabela(self):
        cifrado = cifrar('x', gerar_chave())
        antes = EventoSeguranca.objects.count()
        with silenciar_eventos():
            for _ in range(20):
                try:
                    decifrar(cifrado, gerar_chave())
                except Exception:
                    pass
        self.assertEqual(EventoSeguranca.objects.count(), antes)


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    },
)
class LoginGeraEventosTests(TestCase):
    def setUp(self):
        User.objects.create_user('ana', 'ana@example.com', 'SenhaForte@123')

    def test_falha_e_sucesso_de_login(self):
        with mock.patch('apps.views.recaptcha_valido', return_value=True):
            self.client.post(reverse('login'), {'email': 'ana@example.com', 'password': 'errada'})
            self.client.post(reverse('login'), {'email': 'ninguem@example.com', 'password': 'x'})
            self.client.post(reverse('login'), {'email': 'ana@example.com', 'password': 'SenhaForte@123'})
        eventos = list(EventoSeguranca.objects.order_by('id'))
        self.assertEqual([e.tipo for e in eventos], ['login_falha', 'login_falha', 'login_sucesso'])
        self.assertEqual(eventos[0].detalhes['motivo'], 'senha_incorreta')
        self.assertEqual(eventos[1].detalhes['motivo'], 'email_nao_cadastrado')
        self.assertEqual(eventos[0].ip, '127.0.0.1')
        # e-mail digitado é pseudonimizado (LGPD), nunca gravado em claro
        self.assertTrue(eventos[0].usuario.startswith('usr_'))
        self.assertNotIn('@', eventos[1].usuario)
        # a senha digitada nunca vai para a tabela
        self.assertNotIn('errada', str(list(EventoSeguranca.objects.values_list('detalhes', 'usuario'))))


class AnaliseTests(TestCase):
    def test_gerador_resumo_e_features(self):
        call_command('gerar_eventos_simulados', qtd=800, dias=3, anomalias=10, stdout=StringIO())
        r = ae.resumo_geral()
        self.assertGreater(r['total'], 800)
        self.assertIn('login_falha', r['por_tipo'])
        feats = ae.features_por_janela(5)
        brutas = [f for f in feats if f['cenario_simulado'] == 'forca_bruta_login']
        normais = [f for f in feats if f['cenario_simulado'] == 'normal']
        self.assertTrue(brutas)
        self.assertGreater(max(f['login_falha'] for f in brutas), max(f['login_falha'] for f in normais))
        call_command('gerar_eventos_simulados', limpar=True, stdout=StringIO())
        self.assertEqual(EventoSeguranca.objects.count(), 0)

    def test_gerador_e_reproduzivel(self):
        args = dict(qtd=200, dias=2, anomalias=5, seed=7, stdout=StringIO())
        call_command('gerar_eventos_simulados', **args)
        n1 = EventoSeguranca.objects.count()
        call_command('gerar_eventos_simulados', limpar=True, stdout=StringIO())
        call_command('gerar_eventos_simulados', **args)
        self.assertEqual(EventoSeguranca.objects.count(), n1)

    def test_importar_log_e_idempotente(self):
        linhas = (
            '2026-09-14 11:15:44,270 [WARNING] Login falhou (senha incorreta): email=a@x.local ip=127.0.0.1\n'
            '2026-09-14 11:15:45,466 [INFO] Login bem-sucedido: usuario=cliente ip=127.0.0.1\n'
            '2026-09-14 11:15:45,490 [WARNING] Acesso negado: usuario=cliente tentou cadastrar cafeteria\n'
            '2026-09-14 11:15:44,270 [WARNING] Login falhou (senha incorreta): email=a@x.local ip=127.0.0.1\n'
            '2026-09-14 11:16:00,000 [INFO] linha sem regra\n'
        )
        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False, encoding='utf-8') as f:
            f.write(linhas)
        try:
            call_command('importar_logs_seguranca', arquivo=f.name, stdout=StringIO())
            call_command('importar_logs_seguranca', arquivo=f.name, stdout=StringIO())
        finally:
            os.unlink(f.name)
        # 4 linhas com regra (2 idênticas, ambas preservadas); a 2ª rodada não duplica.
        self.assertEqual(EventoSeguranca.objects.count(), 4)
        self.assertEqual(EventoSeguranca.objects.filter(tipo='login_falha', ip='127.0.0.1').count(), 2)
        self.assertFalse(EventoSeguranca.objects.filter(usuario__contains='@').exists())

    def test_exportar_csv(self):
        registrar_evento('login_falha', usuario='a', ip='1.1.1.1')
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e.csv')
        call_command('analisar_eventos', csv=out, features_csv=os.path.join(d, 'f.csv'), stdout=StringIO())
        with open(out, encoding='utf-8-sig') as f:
            self.assertIn('login_falha', f.read())
