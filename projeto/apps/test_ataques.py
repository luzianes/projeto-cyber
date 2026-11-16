import base64
import json
import os
import tempfile
from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase

from . import ataques_cripto as ac
from . import mensageria_cripto as mc
from .models import EventoSeguranca


class CifrarComIvTests(SimpleTestCase):
    def test_reproduz_cifrar_byte_a_byte(self):
        # Garante que os ataques com IV fixo atacam a cifra real, não uma cópia diferente.
        chave = mc.gerar_chave()
        iv = bytes(range(8))
        for texto in ('', 'a', 'Mensagem com acentuação e mais de um bloco!'):
            with mock.patch('apps.mensageria_cripto.os.urandom', return_value=iv), \
                    mock.patch('apps.mensageria_cripto.registrar_evento'):
                real = base64.urlsafe_b64decode(mc.cifrar(texto, chave))
            self.assertEqual(ac.cifrar_com_iv(texto.encode(), base64.urlsafe_b64decode(chave), iv), real)


class DiferencialTests(TestCase):
    def test_nao_ha_efeito_avalanche(self):
        r = ac.ataque_diferencial(amostras=20)
        self.assertFalse(r['tem_avalanche'])
        self.assertLess(r['texto']['percentual_bits'], 15)
        self.assertEqual(r['texto']['bytes_alterados_max'], 1)
        # cada byte de entrada afeta exatamente um byte de saída (é só uma permutação)
        mapa = r['texto']['mapa_entrada_saida']
        self.assertTrue(all(len(s) == 1 for s in mapa))
        self.assertEqual(sorted(s[0] for s in mapa), list(range(mc.TAMANHO_BLOCO)))
        self.assertTrue(r['mensagem_cbc']['blocos_anteriores_intactos'])
        self.assertLess(r['chave']['percentual_bits'], 45)

    def test_comparacao_ingenua_engana(self):
        r = ac.ataque_diferencial(amostras=20)
        self.assertGreater(r['ingenuo_iv_aleatorio']['percentual_bits'], 40)

    def test_maleabilidade(self):
        mal = ac.ataque_diferencial(amostras=4)['maleabilidade']
        self.assertTrue(mal['maleavel'])
        self.assertEqual(mal['adulterado'], 'Para 9 pessoas, sábado às 20h.')

    def test_uniformidade_diferencial_sbox(self):
        self.assertGreaterEqual(ac.uniformidade_diferencial_sbox(), 4)


class ForcaBrutaTests(TestCase):
    def test_trilhas_formam_permutacao(self):
        trilhas = ac.trilhas()
        self.assertEqual(sorted(p for p, _ in trilhas), list(range(mc.TAMANHO_BLOCO)))
        self.assertTrue(all(len(indices) == mc.NUM_RODADAS for _, indices in trilhas))

    def test_quebra_chave_reduzida_e_chave_completa(self):
        r = ac.ataque_forca_bruta(bytes_desconhecidos=1, blocos_conhecidos=3)
        self.assertTrue(r['reduzida']['quebrou'])
        self.assertLessEqual(r['reduzida']['tentativas'], 256)
        self.assertTrue(r['dividir_conquistar']['quebrou'])
        self.assertIn('CAFE-7Q2X-91', r['dividir_conquistar']['texto_recuperado'])
        self.assertEqual(r['estimativa']['espaco_chaves_bits'], 64)
        self.assertGreater(r['estimativa']['anos_caso_medio'], 1)
        self.assertTrue(r['vulnerabilidade_encontrada'])

    def test_recuperar_chave_exige_dois_blocos(self):
        cifrado = mc.cifrar('qualquer coisa', mc.gerar_chave())
        with self.assertRaises(ValueError):
            ac.recuperar_chave(cifrado, b'12345678')

    def test_modo_ataque_nao_suja_tabela_nem_log(self):
        cifrado = mc.cifrar('Oi', ac._b64(bytes(7) + b'\x99'))
        antes = EventoSeguranca.objects.count()
        with self.assertNoLogs('security', level='WARNING'):
            chave, texto, _ = ac.busca_exaustiva(cifrado, bytes(7), 1)
        self.assertEqual((chave, texto), (bytes(7) + b'\x99', 'Oi'))
        self.assertEqual(EventoSeguranca.objects.count(), antes)
        # fora do modo ataque, a falha volta a ser registrada normalmente
        with self.assertLogs('security', level='WARNING'), self.assertRaises(ValueError):
            mc.decifrar(cifrado, ac._b64(bytes(8)))


class EstatisticoTests(TestCase):
    def test_frequencia_do_cifrado_e_uniforme(self):
        r = ac.ataque_estatistico(qtd_mensagens=300)
        self.assertGreater(r['texto_cifrado']['entropia_bits_por_byte'], 7.9)
        self.assertGreater(r['texto_cifrado']['p_valor'], 1e-4)
        self.assertLess(r['texto_claro']['p_valor'], 1e-6)
        self.assertEqual(r['blocos_repetidos']['distintos_com_cbc'], 8)
        self.assertEqual(r['blocos_repetidos']['distintos_sem_cbc'], 1)
        self.assertTrue(r['resumo']['vaza_tamanho'])
        self.assertFalse(r['vulnerabilidade_encontrada'])


class ComandoRodarAtaquesTests(TestCase):
    opcoes = dict(bytes_desconhecidos=1, amostras=10, mensagens=100)

    def test_registra_um_evento_por_ataque_sem_vazar_segredo(self):
        caminho = os.path.join(tempfile.mkdtemp(), 'ataques.json')
        call_command('rodar_ataques', json=caminho, stdout=StringIO(), **self.opcoes)
        eventos = EventoSeguranca.objects.all()
        self.assertEqual(sorted(e.tipo for e in eventos),
                         ['ataque_diferencial', 'ataque_estatistico', 'ataque_forca_bruta'])
        self.assertTrue(all(e.origem == 'ataques_cripto' and e.categoria == 'ataque' for e in eventos))
        self.assertTrue(eventos.get(tipo='ataque_forca_bruta').sucesso)
        self.assertFalse(eventos.get(tipo='ataque_estatistico').sucesso)
        tudo = json.dumps([e.detalhes for e in eventos], ensure_ascii=False)
        self.assertNotIn('CAFE-7Q2X', tudo)
        self.assertNotIn('pessoas', tudo)
        with open(caminho, encoding='utf-8') as f:
            veredito = json.load(f)['veredito']
        self.assertFalse(veredito['tem_avalanche'])
        self.assertFalse(veredito['seguro'])

    def test_nao_registrar_e_ataque_unico(self):
        saida = StringIO()
        call_command('rodar_ataques', ataque=['diferencial'], nao_registrar=True, stdout=saida,
                     **self.opcoes)
        self.assertEqual(EventoSeguranca.objects.count(), 0)
        self.assertIn('Efeito avalanche: NÃO', saida.getvalue())
        self.assertNotIn('Veredito', saida.getvalue())

    def test_valida_parametros(self):
        with self.assertRaises(CommandError):
            call_command('rodar_ataques', blocos_conhecidos=1, stdout=StringIO())
