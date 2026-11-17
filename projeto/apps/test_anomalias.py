import json
import os
import random
import tempfile
from datetime import timedelta
from importlib.util import find_spec
from io import StringIO
from unittest import skipUnless

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from . import deteccao_anomalias as da
from .analise_eventos import features_por_janela
from .eventos import registrar_evento
from .models import EventoSeguranca
from .painel import dados_painel

TEM_SKLEARN = find_spec('sklearn') is not None
precisa_sklearn = skipUnless(TEM_SKLEARN, 'scikit-learn não instalado (pip install -r requirements-ia.txt)')


def linha(entidade='10.0.0.1', minuto=0, cenario='', **contagens):
    """Uma linha no formato de features_por_janela(), com zeros por padrão."""
    base = {c: 0 for c in da.COLUNAS}
    base.update(contagens)
    base['total'] = contagens.get('total', sum(v for k, v in contagens.items() if k in da.TIPOS_FEATURE))
    tentativas = base['login_sucesso'] + base['login_falha'] + base['login_bloqueado']
    base['taxa_falha_login'] = (base['login_falha'] + base['login_bloqueado']) / tentativas if tentativas else 0.0
    base['usuarios_distintos'] = contagens.get('usuarios_distintos', 1)
    inicio = timezone.now().replace(microsecond=0) - timedelta(days=1) + timedelta(minutes=5 * minuto)
    return {**base, 'entidade': entidade, 'janela_inicio': inicio.isoformat(),
            'hora_do_dia': inicio.hour, 'cenario_simulado': cenario}


def trafego_normal(n=400, semente=1):
    rng = random.Random(semente)
    linhas = []
    for i in range(n):
        linhas.append(linha(
            entidade=f'10.0.0.{i % 40 + 2}', minuto=i, cenario='normal',
            login_sucesso=rng.randint(0, 2), cifragem=rng.randint(1, 3), decifragem=rng.randint(1, 3),
            login_falha=1 if rng.random() < 0.05 else 0,
        ))
    return linhas


class RegrasTests(SimpleTestCase):
    """Camada de assinatura: não depende do scikit-learn nem de volume de dados."""

    def test_poucas_janelas_usa_so_regras(self):
        linhas = [linha(cifragem=3), linha(entidade='', integridade_violada=2, minuto=1),
                  linha(entidade='203.0.113.9', login_falha=40, minuto=2)]
        resultados, info = da.detectar(linhas)
        self.assertFalse(info['modelo_usado'])
        self.assertEqual([r['anomala'] for r in resultados], [False, True, True])
        self.assertEqual(resultados[1]['motivo'], 'regra_integridade_violada')
        self.assertEqual(resultados[2]['motivo'], 'regra_forca_bruta_login')
        self.assertEqual(resultados[2]['metodo'], 'regra')
        self.assertEqual(resultados[2]['destaques']['login_falha'], {'valor': 40, 'limiar': 10})

    def test_abaixo_do_limiar_nao_dispara_regra(self):
        resultados, _ = da.detectar([linha(login_falha=9, falha_decifragem=9, acesso_negado=9)])
        self.assertFalse(resultados[0]['pred_regra'])

    def test_metricas(self):
        m = da._metricas([True, True, False, False], [True, False, True, False])
        self.assertEqual((m['vp'], m['fp'], m['fn'], m['vn']), (1, 1, 1, 1))
        self.assertEqual((m['precisao'], m['recall'], m['f1']), (0.5, 0.5, 0.5))


@precisa_sklearn
class IsolationForestTests(SimpleTestCase):

    def test_pega_combinacao_que_nenhuma_regra_cobre(self):
        # 8 falhas de login + 8 de decifragem + 8 acessos negados em 5 min:
        # cada contagem fica abaixo do limiar de 10, nenhuma regra dispara.
        # É o caso em que a camada comportamental se justifica.
        ataque = linha(entidade='203.0.113.50', minuto=999, cenario='novo',
                       login_falha=8, falha_decifragem=8, acesso_negado=8, usuarios_distintos=6)
        linhas = trafego_normal() + [ataque]
        resultados, info = da.detectar(linhas)
        r = resultados[-1]
        self.assertTrue(info['modelo_usado'])
        self.assertFalse(r['pred_regra'])
        self.assertTrue(r['pred_modelo'])
        self.assertEqual(r['metodo'], 'isolation_forest')
        self.assertTrue(r['destaques'])
        # O ataque fica entre as janelas mais anômalas do conjunto.
        scores = sorted((x['score'] for x in resultados if x['score'] is not None), reverse=True)
        self.assertLessEqual(scores.index(r['score']), 2)

    def test_reprodutivel(self):
        linhas = trafego_normal() + [linha(entidade='203.0.113.1', minuto=999, login_falha=50)]
        a, _ = da.detectar(linhas)
        b, _ = da.detectar(linhas)
        self.assertEqual([x['score'] for x in a], [x['score'] for x in b])

    def test_janela_pequena_nao_vai_ao_modelo(self):
        linhas = trafego_normal() + [linha(entidade='10.9.9.9', minuto=999, cifragem=1)]
        resultados, _ = da.detectar(linhas)
        self.assertIsNone(resultados[-1]['score'])


@precisa_sklearn
class ExecucaoTests(TestCase):

    def _gerar(self):
        call_command('gerar_eventos_simulados', qtd=6000, dias=2, anomalias=10, seed=3, stdout=StringIO())

    def test_grava_alertas_sem_duplicar_e_sem_contar_os_proprios(self):
        self._gerar()
        features_antes = features_por_janela(5, excluir_tipos=da.TIPOS_IGNORADOS)
        primeira = da.executar()
        self.assertGreater(primeira['novas'], 0)
        alertas = EventoSeguranca.objects.filter(tipo='anomalia', origem=da.ORIGEM)
        self.assertEqual(alertas.count(), primeira['novas'])
        # Os alertas gravados não mudam as features da próxima execução...
        self.assertEqual(features_por_janela(5, excluir_tipos=da.TIPOS_IGNORADOS), features_antes)
        # ...e rodar de novo não duplica.
        segunda = da.executar()
        self.assertEqual(segunda['novas'], 0)
        self.assertEqual(segunda['repetidas'], primeira['novas'])
        self.assertEqual(alertas.count(), primeira['novas'])

    def test_alerta_tem_metadados_e_data_da_janela(self):
        self._gerar()
        da.executar()
        e = EventoSeguranca.objects.filter(tipo='anomalia').first()
        for campo in ('entidade', 'janela_inicio', 'metodo', 'motivo', 'descricao', 'destaques', 'id_janela'):
            self.assertIn(campo, e.detalhes)
        self.assertEqual(e.criado_em.isoformat(), e.detalhes['janela_inicio'])
        self.assertTrue(e.simulado)
        self.assertFalse(e.sucesso)

    def test_comando_avalia_e_exporta_json(self):
        self._gerar()
        destino = os.path.join(tempfile.mkdtemp(), 'r.json')
        out = StringIO()
        call_command('detectar_anomalias', avaliar=True, nao_gravar=True, json=destino, stdout=out)
        self.assertIn('Avaliação contra o gabarito', out.getvalue())
        self.assertFalse(EventoSeguranca.objects.filter(tipo='anomalia').exists())
        with open(destino, encoding='utf-8') as f:
            av = json.load(f)['avaliacao']
        self.assertGreater(av['janelas_anomalas'], 0)
        self.assertGreater(av['hibrido']['recall'], 0.5)
        # O híbrido nunca pega menos que as regras sozinhas (é a união das duas camadas).
        self.assertGreaterEqual(av['hibrido']['recall'], av['regras']['recall'])

    def test_limpar(self):
        self._gerar()
        da.executar()
        call_command('detectar_anomalias', limpar=True, stdout=StringIO())
        self.assertFalse(EventoSeguranca.objects.filter(tipo='anomalia').exists())
        self.assertTrue(EventoSeguranca.objects.exists())


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    },
)
class PainelTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user('equipe', 'eq@example.com', 'SenhaForte@123', is_staff=True)
        self.comum = User.objects.create_user('cliente', 'cl@example.com', 'SenhaForte@123')
        self.url = reverse('painel_seguranca')

    def test_anonimo_vai_para_login(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse('login'), r['Location'])

    def test_usuario_comum_recebe_403_e_gera_evento(self):
        self.client.force_login(self.comum)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        e = EventoSeguranca.objects.get(tipo='acesso_negado')
        self.assertEqual((e.usuario, e.origem, e.detalhes['motivo']), ('cliente', 'painel_seguranca', 'nao_staff'))

    def test_staff_ve_painel_vazio(self):
        self.client.force_login(self.staff)
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Ainda não há eventos')

    def test_staff_ve_anomalias_e_ataques(self):
        registrar_evento('login_falha', usuario='x', ip='203.0.113.7')
        registrar_evento('anomalia', ip='203.0.113.7', origem=da.ORIGEM, severidade='critico',
                         detalhes={'entidade': '203.0.113.7', 'descricao': 'número incomum de falhas de login',
                                   'metodo': 'regra', 'score': None,
                                   'destaques': {'login_falha': {'valor': 40, 'limiar': 10}}})
        registrar_evento('ataque_forca_bruta', origem='ataques_cripto', sucesso=True, duracao_ms=1200,
                         detalhes={'espaco_chaves_bits': 64, 'parametros': {'x': 1}})
        self.client.force_login(self.staff)
        r = self.client.get(self.url, {'dias': 7})
        self.assertContains(r, '203.0.113.7')
        self.assertContains(r, 'número incomum de falhas de login')
        self.assertContains(r, 'Vulnerável')
        self.assertContains(r, 'espaco_chaves_bits')
        self.assertNotContains(r, 'parametros')
        self.assertContains(r, 'id="dados-graficos"')

    def test_parametros_invalidos_caem_no_padrao(self):
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(self.url, {'dias': 'abc'}).status_code, 200)
        self.assertEqual(self.client.get(self.url, {'dias': '999'}).status_code, 200)

    def test_dados_escapados_no_json(self):
        # Origem controlada por atacante (usuario é texto livre) não pode virar HTML/script.
        registrar_evento('anomalia', usuario='</script><script>alert(1)</script>', origem=da.ORIGEM,
                         detalhes={'descricao': '<b>x</b>', 'metodo': 'regra'})
        self.client.force_login(self.staff)
        r = self.client.get(self.url)
        self.assertNotContains(r, '<script>alert(1)</script>')
        self.assertNotContains(r, '<b>x</b>')

    def test_filtro_sem_simulados(self):
        registrar_evento('anomalia', origem=da.ORIGEM, simulado=True, detalhes={'descricao': 'a'})
        registrar_evento('anomalia', origem=da.ORIGEM, simulado=False, detalhes={'descricao': 'b'})
        self.assertEqual(dados_painel(incluir_simulados=True)['kpis']['anomalias'], 2)
        self.assertEqual(dados_painel(incluir_simulados=False)['kpis']['anomalias'], 1)
