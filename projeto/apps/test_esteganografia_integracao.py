"""Integração real entre a cifra existente, LSB, auditoria e HTTP autenticado."""
import base64
import json
import tempfile
from io import BytesIO
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from PIL import Image

from . import esteganografia_servico as servico
from . import mensageria_cripto as mc
from .esteganografia import (
    ErroEsteganografia, TAMANHO_CABECALHO, carregar_imagem,
    extrair_texto, ocultar_texto,
)
from .models import EventoSeguranca


CHAVE = base64.urlsafe_b64encode(b'01234567').decode('ascii')
OUTRA_CHAVE = base64.urlsafe_b64encode(b'76543210').decode('ascii')
MENSAGEM = '  Olá, Recife! ☕\n漢字 e emoji 🔐\x00fim  \n'


def imagem_png(tamanho=(160, 120), modo='RGB'):
    """Imagem sintética local; testes nunca dependem de imagens externas."""
    imagem = Image.new(modo, tamanho, (72, 131, 212, 93) if modo == 'RGBA' else (72, 131, 212))
    arquivo = BytesIO()
    imagem.save(arquivo, format='PNG')
    return arquivo.getvalue()


def arquivo_imagem(dados=None, nome='imagem.png'):
    return SimpleUploadedFile(nome, dados if dados is not None else imagem_png(), content_type='image/png')


class FluxoEsteganografiaTests(TestCase):
    def test_reutiliza_cifra_e_recupera_unicode_espacos_e_bytes_nulos(self):
        with mock.patch.object(mc, 'cifrar', wraps=mc.cifrar) as cifrar:
            oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, CHAVE)
        cifrar.assert_called_once()
        self.assertEqual(cifrar.call_args.args[:2], (MENSAGEM, CHAVE))
        self.assertEqual(oculto['chave'], CHAVE)
        self.assertEqual(mc.decifrar(oculto['texto_cifrado'], CHAVE), MENSAGEM)
        with mock.patch.object(mc, 'decifrar', wraps=mc.decifrar) as decifrar:
            recuperado = servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']), CHAVE)
        decifrar.assert_called_once()
        self.assertEqual(recuperado['texto_cifrado'], oculto['texto_cifrado'])
        self.assertEqual(recuperado['mensagem'], MENSAGEM)

    def test_chave_gerada_pode_ser_utilizada_posteriormente(self):
        oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM)
        self.assertEqual(len(base64.urlsafe_b64decode(oculto['chave'])), mc.TAMANHO_CHAVE)
        recuperado = servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']), oculto['chave'])
        self.assertEqual(recuperado['mensagem'], MENSAGEM)

    def test_extracao_sem_chave_recupera_cifrado_sem_decifrar(self):
        oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, CHAVE)
        with mock.patch.object(mc, 'decifrar') as decifrar:
            recuperado = servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']))
        decifrar.assert_not_called()
        self.assertEqual(recuperado['texto_cifrado'], oculto['texto_cifrado'])
        self.assertIsNone(recuperado['mensagem'])

    def test_chave_errada_falha_antes_de_decifrar_e_alimenta_auditoria(self):
        oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, CHAVE)
        with mock.patch.object(mc, 'decifrar') as decifrar:
            with self.assertRaises(ErroEsteganografia):
                servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']), OUTRA_CHAVE, usuario='ana')
        decifrar.assert_not_called()
        self.assertTrue(EventoSeguranca.objects.filter(tipo='falha_decifragem', sucesso=False, usuario='ana').exists())
        self.assertTrue(EventoSeguranca.objects.filter(tipo='esteganografia', sucesso=False, usuario='ana').exists())

    def test_rejeita_chaves_malformadas_antes_da_cifra(self):
        invalidas = ('nao-e-uma-chave', '!', 'á' * 12,
                     base64.urlsafe_b64encode(b'curta').decode(),
                     base64.urlsafe_b64encode(b'012345678').decode())
        with mock.patch.object(mc, 'cifrar') as cifrar:
            for chave in invalidas:
                with self.subTest(chave=chave), self.assertRaises(ErroEsteganografia):
                    servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, chave)
        cifrar.assert_not_called()

    def test_recusa_excesso_de_capacidade_antes_de_cifrar(self):
        with mock.patch.object(mc, 'cifrar') as cifrar:
            with self.assertRaises(ErroEsteganografia):
                servico.ocultar_mensagem(arquivo_imagem(imagem_png((10, 10))), MENSAGEM, CHAVE)
        cifrar.assert_not_called()

    def test_limite_de_mensagem_e_medido_em_bytes_utf8(self):
        mensagem = 'é' * (servico.MAX_MENSAGEM_BYTES // 2 + 1)
        self.assertLess(len(mensagem), servico.MAX_MENSAGEM_BYTES)
        with mock.patch.object(mc, 'cifrar') as cifrar:
            with self.assertRaises(ErroEsteganografia):
                servico.ocultar_mensagem(arquivo_imagem(), mensagem, CHAVE)
        cifrar.assert_not_called()

    def test_mensagem_no_limite_com_imagem_suficiente(self):
        mensagem = 'x' * servico.MAX_MENSAGEM_BYTES
        oculto = servico.ocultar_mensagem(arquivo_imagem(imagem_png((600, 600))), mensagem, CHAVE)
        recuperado = servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']), CHAVE)
        self.assertEqual(recuperado['mensagem'], mensagem)

    def test_rejeita_mensagem_vazia_e_arquivo_invalido(self):
        with self.assertRaises(ErroEsteganografia):
            servico.ocultar_mensagem(arquivo_imagem(), '', CHAVE)
        for dados in (b'', b'nao sou PNG'):
            with self.subTest(dados=dados), self.assertRaises(ErroEsteganografia):
                servico.extrair_mensagem(arquivo_imagem(dados), CHAVE)

    def test_rejeita_imagem_sem_dados(self):
        with self.assertRaises(ErroEsteganografia):
            servico.extrair_mensagem(arquivo_imagem(), CHAVE)

    def test_corrupcao_de_um_bit_na_carga_e_detectada(self):
        oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, CHAVE)
        imagem = carregar_imagem(BytesIO(oculto['imagem_png']))
        indice_canal = TAMANHO_CABECALHO * 8 + 5
        pixel, canal = divmod(indice_canal, 3)
        y, x = divmod(pixel, imagem.width)
        cor = list(imagem.getpixel((x, y)))
        cor[canal] ^= 1
        imagem.putpixel((x, y), tuple(cor))
        arquivo = BytesIO()
        imagem.save(arquivo, format='PNG')
        with mock.patch.object(mc, 'decifrar') as decifrar:
            with self.assertRaises(ErroEsteganografia):
                servico.extrair_mensagem(arquivo_imagem(arquivo.getvalue()), CHAVE)
        decifrar.assert_not_called()

    def test_recalcular_checksum_publico_nao_contorna_autenticacao(self):
        oculto = servico.ocultar_mensagem(arquivo_imagem(), MENSAGEM, CHAVE)
        imagem = carregar_imagem(BytesIO(oculto['imagem_png']))
        envelope = json.loads(extrair_texto(imagem))
        envelope['h'] = ('0' if envelope['h'][0] != '0' else '1') + envelope['h'][1:]
        adulterada = ocultar_texto(imagem, json.dumps(envelope, separators=(',', ':'))).png
        # O checksum LSB é válido novamente, mas o HMAC continua inválido.
        with mock.patch.object(mc, 'decifrar') as decifrar:
            with self.assertRaises(ErroEsteganografia):
                servico.extrair_mensagem(arquivo_imagem(adulterada), CHAVE)
        decifrar.assert_not_called()

    def test_rejeita_envelopes_invalidos_mesmo_com_checksum_lsb_valido(self):
        envelopes = ('nao-json', '{}', '{"v":99,"c":"YQ==","h":"' + '0' * 64 + '"}',
                     '{"v":1,"c":"!","h":"' + '0' * 64 + '"}')
        for envelope in envelopes:
            with self.subTest(envelope=envelope):
                imagem = carregar_imagem(BytesIO(imagem_png()))
                png = ocultar_texto(imagem, envelope).png
                with self.assertRaises(ErroEsteganografia):
                    servico.extrair_mensagem(arquivo_imagem(png), CHAVE)

    def test_metricas_preservam_dimensoes_alpha_e_qualidade_rgb(self):
        original = imagem_png(modo='RGBA')
        oculto = servico.ocultar_mensagem(arquivo_imagem(original), MENSAGEM, CHAVE)
        with Image.open(BytesIO(oculto['imagem_png'])) as modificada, Image.open(BytesIO(original)) as antes:
            self.assertEqual(modificada.format, 'PNG')
            self.assertEqual(modificada.size, antes.size)
            self.assertEqual(modificada.getchannel('A').tobytes(), antes.getchannel('A').tobytes())
            diferencas = [abs(a - b) for a, b in zip(antes.convert('RGB').tobytes(), modificada.convert('RGB').tobytes())]
        metricas = oculto['metricas']
        mse = sum(d * d for d in diferencas) / len(diferencas)
        self.assertEqual(max(diferencas), 1)
        self.assertAlmostEqual(metricas['mse'], mse, places=6)
        self.assertGreaterEqual(metricas['psnr'], 48.13)
        self.assertEqual((metricas['largura'], metricas['altura']), (160, 120))
        self.assertEqual(metricas['utilizados_bits'], (metricas['payload_bytes'] + TAMANHO_CABECALHO) * 8)
        self.assertLessEqual(metricas['payload_bytes'], metricas['capacidade_bytes'])

    def test_eventos_contem_resultado_capacidade_e_duracao_sem_segredos(self):
        mensagem = 'TEXTO_SUPER_SECRETO_LSB'
        oculto = servico.ocultar_mensagem(arquivo_imagem(), mensagem, CHAVE, usuario='ana', ip='127.0.0.2')
        servico.extrair_mensagem(arquivo_imagem(oculto['imagem_png']), CHAVE, usuario='ana', ip='127.0.0.2')
        eventos = list(EventoSeguranca.objects.filter(tipo='esteganografia').order_by('id'))
        self.assertEqual(len(eventos), 2)
        self.assertEqual([e.detalhes['operacao'] for e in eventos], ['ocultacao', 'extracao'])
        for evento in eventos:
            self.assertEqual(evento.categoria, 'esteganografia')
            self.assertTrue(evento.sucesso)
            self.assertEqual(evento.usuario, 'ana')
            self.assertEqual(evento.ip, '127.0.0.2')
            self.assertGreaterEqual(evento.duracao_ms, 0)
            self.assertEqual(evento.detalhes['resultado'], 'sucesso')
            for campo in ('capacidade_bytes', 'payload_bytes', 'utilizados_bits', 'capacidade_utilizada_percentual'):
                self.assertIn(campo, evento.detalhes)
        detalhes = json.dumps(list(EventoSeguranca.objects.values_list('detalhes', flat=True)))
        for segredo in (mensagem, CHAVE, oculto['texto_cifrado']):
            self.assertNotIn(segredo, detalhes)

    def test_falhas_registram_apenas_motivo_seguro(self):
        with self.assertRaises(ErroEsteganografia):
            servico.ocultar_mensagem(arquivo_imagem(b'CONTEUDO_SECRETO_INVALIDO'), MENSAGEM, CHAVE)
        evento = EventoSeguranca.objects.get(tipo='esteganografia')
        self.assertFalse(evento.sucesso)
        self.assertEqual(evento.detalhes['resultado'], 'falha')
        self.assertTrue(evento.detalhes['motivo'])
        self.assertGreaterEqual(evento.duracao_ms, 0)
        detalhes = json.dumps(evento.detalhes)
        for segredo in ('CONTEUDO_SECRETO_INVALIDO', MENSAGEM, CHAVE):
            self.assertNotIn(segredo, detalhes)


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    STORAGES={
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    },
)
class InterfaceEsteganografiaTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.usuario = User.objects.create_user('usuario-lsb', password='SenhaLSB@123')

    def setUp(self):
        self.client.force_login(self.usuario)

    def test_pagina_integrada_e_endpoints_exigem_login(self):
        cliente = Client()
        for nome in ('esteganografia', 'esteganografia_ocultar', 'esteganografia_extrair'):
            with self.subTest(nome=nome):
                resposta = cliente.get(reverse(nome)) if nome == 'esteganografia' else cliente.post(reverse(nome))
                self.assertEqual(resposta.status_code, 302)
                self.assertIn(reverse('login'), resposta['Location'])
        pagina = self.client.get(reverse('esteganografia'))
        self.assertEqual(pagina.status_code, 200)
        self.assertTemplateUsed(pagina, 'esteganografia.html')
        self.assertContains(pagina, 'csrfmiddlewaretoken')
        self.assertIn('no-store', pagina['Cache-Control'])

    def test_operacoes_rejeitam_get(self):
        for nome in ('esteganografia_ocultar', 'esteganografia_extrair'):
            with self.subTest(nome=nome):
                self.assertEqual(self.client.get(reverse(nome)).status_code, 405)

    def test_fluxo_http_png_e_mensagem_integral_sem_persistir_arquivos_ou_segredos(self):
        with tempfile.TemporaryDirectory() as pasta, override_settings(MEDIA_ROOT=pasta):
            resposta = self.client.post(reverse('esteganografia_ocultar'), {
                'imagem': arquivo_imagem(), 'mensagem': MENSAGEM, 'chave': CHAVE,
            })
            self.assertEqual(resposta.status_code, 200)
            self.assertIn('no-store', resposta['Cache-Control'])
            dados = resposta.json()
            self.assertTrue(dados['sucesso'])
            png = base64.b64decode(dados['imagem_base64'], validate=True)
            self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
            extraida = self.client.post(reverse('esteganografia_extrair'), {'imagem': arquivo_imagem(png), 'chave': CHAVE})
            self.assertEqual(extraida.status_code, 200)
            self.assertIn('no-store', extraida['Cache-Control'])
            self.assertEqual(extraida.json()['mensagem'], MENSAGEM)
            self.assertEqual(extraida.json()['texto_cifrado'], dados['texto_cifrado'])
            self.assertEqual(list(Path(pasta).iterdir()), [])
        sessao = json.dumps(dict(self.client.session), ensure_ascii=False)
        for segredo in (MENSAGEM, CHAVE, dados['texto_cifrado'], dados['imagem_base64']):
            self.assertNotIn(segredo, sessao)

    def test_csrf_e_obrigatorio_e_formulario_fornece_token_valido(self):
        cliente = Client(enforce_csrf_checks=True)
        cliente.force_login(self.usuario)
        resposta = cliente.post(reverse('esteganografia_ocultar'), {'imagem': arquivo_imagem(), 'mensagem': MENSAGEM})
        self.assertEqual(resposta.status_code, 403)
        cliente.get(reverse('esteganografia'))
        token = cliente.cookies['csrftoken'].value
        resposta = cliente.post(reverse('esteganografia_ocultar'), {
            'imagem': arquivo_imagem(), 'mensagem': MENSAGEM, 'csrfmiddlewaretoken': token,
        })
        self.assertEqual(resposta.status_code, 200)
        self.assertTrue(resposta.json()['sucesso'])

    def test_mensagem_json_preserva_lf_crlf_unicode_nulos_e_tabs_no_http(self):
        mensagem = '  Acentuação: café ☕\nlinha LF\r\nlinha CRLF\t漢字\x00fim\n  '
        resposta = self.client.post(reverse('esteganografia_ocultar'), {
            'imagem': arquivo_imagem(), 'mensagem_json': json.dumps(mensagem, ensure_ascii=False),
            'chave': CHAVE,
        })
        self.assertEqual(resposta.status_code, 200)
        png = base64.b64decode(resposta.json()['imagem_base64'])
        extraida = self.client.post(reverse('esteganografia_extrair'), {
            'imagem': arquivo_imagem(png), 'chave': CHAVE,
        })
        self.assertEqual(extraida.status_code, 200)
        self.assertEqual(extraida.json()['mensagem'], mensagem)
        self.assertEqual(extraida.json()['mensagem'].encode('utf-8'), mensagem.encode('utf-8'))

    def test_mensagem_json_tem_precedencia_sobre_campo_multipart_normalizado(self):
        mensagem = 'primeira\nsegunda\n'
        resposta = self.client.post(reverse('esteganografia_ocultar'), {
            'imagem': arquivo_imagem(), 'mensagem_json': json.dumps(mensagem),
            'mensagem': mensagem.replace('\n', '\r\n'), 'chave': CHAVE,
        })
        self.assertEqual(resposta.status_code, 200)
        self.assertEqual(mc.decifrar(resposta.json()['texto_cifrado'], CHAVE), mensagem)

    def test_mensagem_json_invalida_ou_nao_textual_rejeitada_sem_refletir_segredos(self):
        segredo = 'SEGREDO_JSON_INVALIDO'
        invalidos = (
            segredo, '"' + segredo, json.dumps([segredo]),
            json.dumps({'mensagem': segredo}), '12345', 'true', 'null',
            json.dumps(chr(0xD800)),  # surrogate isolado não é texto UTF-8 válido
        )
        with mock.patch.object(mc, 'cifrar') as cifrar:
            for indice, mensagem_json in enumerate(invalidos, start=1):
                with self.subTest(mensagem_json=mensagem_json):
                    resposta = self.client.post(reverse('esteganografia_ocultar'), {
                        'imagem': arquivo_imagem(), 'mensagem_json': mensagem_json,
                        'mensagem': 'fallback valido que nao deve ser usado', 'chave': CHAVE,
                    })
                    self.assertEqual(resposta.status_code, 400)
                    self.assertFalse(resposta.json()['sucesso'])
                    self.assertEqual(resposta.json()['codigo'], 'mensagem_invalida')
                    self.assertNotIn(segredo, resposta.content.decode())
                    self.assertNotIn(CHAVE, resposta.content.decode())
                    eventos = EventoSeguranca.objects.filter(tipo='esteganografia', sucesso=False)
                    self.assertEqual(eventos.count(), indice)
                    detalhes = json.dumps(list(eventos.values_list('detalhes', flat=True)))
                    self.assertNotIn(segredo, detalhes)
                    self.assertNotIn(CHAVE, detalhes)
        cifrar.assert_not_called()

    def test_erros_de_entrada_sao_json_seguro(self):
        casos = (
            ('esteganografia_ocultar', {'mensagem': MENSAGEM}),
            ('esteganografia_ocultar', {'imagem': arquivo_imagem(), 'mensagem': ''}),
            ('esteganografia_extrair', {'imagem': arquivo_imagem(b'INVALIDO_SECRETO')}),
            ('esteganografia_extrair', {}),
        )
        for nome, campos in casos:
            with self.subTest(nome=nome, campos=list(campos)):
                resposta = self.client.post(reverse(nome), campos)
                self.assertEqual(resposta.status_code, 400)
                dados = resposta.json()
                self.assertFalse(dados['sucesso'])
                self.assertTrue(dados['erro'])
                self.assertTrue(dados['codigo'])
                self.assertNotIn('INVALIDO_SECRETO', resposta.content.decode())

    def test_erro_inesperado_nao_expoe_mensagem_chave_ou_excecao(self):
        segredo = 'SEGREDO_EXCECAO_LSB'
        with mock.patch.object(mc, 'cifrar', side_effect=RuntimeError(segredo + CHAVE)):
            resposta = self.client.post(reverse('esteganografia_ocultar'), {
                'imagem': arquivo_imagem(), 'mensagem': segredo, 'chave': CHAVE,
            })
        self.assertEqual(resposta.status_code, 500)
        self.assertFalse(resposta.json()['sucesso'])
        for valor in (segredo, CHAVE, 'RuntimeError'):
            self.assertNotIn(valor, resposta.content.decode())
        evento = EventoSeguranca.objects.filter(tipo='esteganografia', sucesso=False).get()
        self.assertNotIn(segredo, json.dumps(evento.detalhes))
        self.assertNotIn(CHAVE, json.dumps(evento.detalhes))
