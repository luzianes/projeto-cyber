import base64
import json
import os
import tempfile
from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase

from . import ataques_cripto as ac
from . import cifra_v1_legada as v1
from . import mensageria_cripto as v2
from .models import EventoSeguranca


class CifrarComIvTests(SimpleTestCase):
    def test_reproduz_cifrar_byte_a_byte(self):
        # Garante que os ataques com IV fixo atacam a cifra real, não uma cópia diferente.
        for cifra in (v1, v2):
            chave = cifra.gerar_chave()
            iv = bytes(range(cifra.TAMANHO_BLOCO))
            for texto in ('', 'a', 'Mensagem com acentuação e mais de um bloco!'):
                with self.subTest(cifra=cifra.VERSAO, texto=texto), \
                        mock.patch.object(cifra.os, 'urandom', return_value=iv), \
                        mock.patch('apps.mensageria_cripto.registrar_evento'):
                    iv_real, corpo, _ = cifra._decompor(cifra.cifrar(texto, chave))
                    esperado = ac.cifrar_com_iv(cifra, texto.encode(), base64.urlsafe_b64decode(chave), iv)
                    self.assertEqual(esperado, iv_real + corpo)


class AntesV1Tests(TestCase):
    """Regressão: os ataques continuam encontrando as falhas da cifra original."""

    def test_sem_avalanche_e_maleavel(self):
        r = ac.ataque_diferencial('v1', amostras=20)
        self.assertFalse(r['tem_avalanche'])
        self.assertLess(r['texto']['percentual_bits'], 15)
        self.assertEqual(r['texto']['bytes_alterados_max'], 1)
        mapa = r['texto']['mapa_entrada_saida']  # só uma permutação de bytes
        self.assertEqual(sorted(s[0] for s in mapa if len(s) == 1), list(range(v1.TAMANHO_BLOCO)))
        self.assertTrue(r['maleabilidade']['maleavel'])
        self.assertEqual(r['maleabilidade']['adulterado'], 'Para 9 pessoas, sábado às 20h.')
        self.assertGreater(r['ingenuo_iv_aleatorio']['percentual_bits'], 40)  # o teste ingênuo engana

    def test_chave_completa_recuperada_byte_a_byte(self):
        self.assertTrue(ac.premissa_dividir_conquistar('v1')[0])
        r = ac.ataque_forca_bruta('v1', bytes_desconhecidos=1, blocos_conhecidos=3)
        self.assertTrue(r['reduzida']['quebrou'])
        self.assertTrue(r['dividir_conquistar']['quebrou'])
        self.assertIn('CAFE-7Q2X-91', r['dividir_conquistar']['texto_recuperado'])
        self.assertTrue(r['vulnerabilidade_encontrada'])

    def test_recuperar_chave_exige_dois_blocos(self):
        cifrado = v1.cifrar('qualquer coisa', v1.gerar_chave())
        with self.assertRaises(ValueError):
            ac.recuperar_chave('v1', cifrado, b'12345678')


class DepoisV2Tests(TestCase):
    """A cifra em uso resiste aos mesmos ataques."""

    def test_tem_avalanche_e_rejeita_adulteracao(self):
        r = ac.ataque_diferencial('v2', amostras=10)
        self.assertTrue(r['tem_avalanche'])
        self.assertTrue(45 <= r['texto']['percentual_bits'] <= 55)
        self.assertTrue(45 <= r['chave']['percentual_bits'] <= 55)
        self.assertGreaterEqual(r['texto']['bytes_alterados_min'], 10)
        self.assertTrue(all(len(s) == v2.TAMANHO_BLOCO for s in r['texto']['mapa_entrada_saida']))
        self.assertFalse(r['maleabilidade']['maleavel'])
        self.assertTrue(r['maleabilidade']['rejeitada'])
        self.assertFalse(r['vulnerabilidade_encontrada'])

    def test_forca_bruta_nao_recupera_a_chave(self):
        aplicavel, motivo = ac.premissa_dividir_conquistar('v2')
        self.assertFalse(aplicavel)
        self.assertIn('todos os 16', motivo)
        r = ac.ataque_forca_bruta('v2', bytes_desconhecidos=1)
        self.assertTrue(r['reduzida']['quebrou'])  # o método funciona com a chave artificialmente reduzida
        self.assertFalse(r['dividir_conquistar']['quebrou'])
        self.assertEqual(r['estimativa']['espaco_chaves_bits'], 128)
        self.assertGreater(r['estimativa']['anos_caso_medio'], 1e20)
        self.assertFalse(r['vulnerabilidade_encontrada'])

    def test_frequencia_do_cifrado_e_uniforme(self):
        r = ac.ataque_estatistico('v2', qtd_mensagens=300)
        self.assertGreater(r['texto_cifrado']['entropia_bits_por_byte'], 7.9)
        self.assertGreater(r['texto_cifrado']['p_valor'], 1e-4)
        self.assertLess(r['texto_claro']['p_valor'], 1e-6)
        self.assertEqual(r['blocos_repetidos']['distintos_com_cbc'], 8)
        self.assertEqual(r['blocos_repetidos']['distintos_sem_cbc'], 1)
        self.assertTrue(r['resumo']['vaza_tamanho'])
        self.assertFalse(r['vulnerabilidade_encontrada'])

    def test_uniformidade_diferencial_sbox(self):
        self.assertGreaterEqual(ac.uniformidade_diferencial_sbox('v2'), 4)


class ModoAtaqueTests(TestCase):
    def test_nao_suja_tabela_nem_log(self):
        chave = bytes(15) + b'\x99'
        cifrado = v2.cifrar('Oi', ac._b64(chave))
        antes = EventoSeguranca.objects.count()
        with self.assertNoLogs('security', level='WARNING'):
            achada, texto, _ = ac.busca_exaustiva('v2', cifrado, bytes(15), 1)
        self.assertEqual((achada, texto), (chave, 'Oi'))
        self.assertEqual(EventoSeguranca.objects.count(), antes)
        # fora do modo ataque, a falha volta a ser registrada normalmente
        with self.assertLogs('security', level='WARNING'), self.assertRaises(ValueError):
            v2.decifrar(cifrado, ac._b64(bytes(16)))


class ComandoRodarAtaquesTests(TestCase):
    opcoes = dict(bytes_desconhecidos=1, amostras=10, mensagens=100)

    def _json(self, **opcoes):
        caminho = os.path.join(tempfile.mkdtemp(), 'ataques.json')
        call_command('rodar_ataques', json=caminho, stdout=StringIO(), **self.opcoes, **opcoes)
        with open(caminho, encoding='utf-8') as f:
            return json.load(f)

    def test_v2_registra_um_evento_por_ataque_sem_vazar_segredo(self):
        veredito = self._json()['veredito']
        self.assertTrue(veredito['tem_avalanche'])
        self.assertTrue(veredito['seguro'])
        eventos = EventoSeguranca.objects.filter(categoria='ataque')
        self.assertEqual(sorted(e.tipo for e in eventos),
                         ['ataque_diferencial', 'ataque_estatistico', 'ataque_forca_bruta'])
        self.assertTrue(all(e.origem == 'ataques_cripto' and e.detalhes['cifra'] == 'v2' for e in eventos))
        self.assertFalse(any(e.sucesso for e in eventos))  # nenhum ataque achou vulnerabilidade
        self.assertFalse(EventoSeguranca.objects.exclude(categoria='ataque').exists())
        tudo = json.dumps([e.detalhes for e in eventos], ensure_ascii=False)
        self.assertNotIn('CAFE-7Q2X', tudo)
        self.assertNotIn('pessoas', tudo)

    def test_v1_nao_registra_e_continua_insegura(self):
        veredito = self._json(cifra='v1')['veredito']
        self.assertFalse(veredito['tem_avalanche'])
        self.assertFalse(veredito['seguro'])
        self.assertEqual(EventoSeguranca.objects.count(), 0)

    def test_nao_registrar_e_ataque_unico(self):
        saida = StringIO()
        call_command('rodar_ataques', ataque=['diferencial'], nao_registrar=True, stdout=saida, **self.opcoes)
        self.assertEqual(EventoSeguranca.objects.count(), 0)
        self.assertIn('Efeito avalanche: SIM', saida.getvalue())
        self.assertNotIn('Veredito', saida.getvalue())

    def test_valida_parametros(self):
        with self.assertRaises(CommandError):
            call_command('rodar_ataques', blocos_conhecidos=1, stdout=StringIO())
        with self.assertRaises(CommandError):
            call_command('rodar_ataques', cifra='v1', bytes_desconhecidos=9, stdout=StringIO())
