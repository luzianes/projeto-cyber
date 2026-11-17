"""Testes do formato binário, limites, fidelidade e validação de uploads LSB."""

from hashlib import sha256
from io import BytesIO
import binascii
import math
import struct
from unittest import mock
import zlib

from django.test import SimpleTestCase
from PIL import Image, ImageChops, PngImagePlugin

from . import esteganografia as lsb


def imagem_bytes(imagem, formato='PNG', **opcoes):
    arquivo = BytesIO()
    imagem.save(arquivo, format=formato, **opcoes)
    return arquivo.getvalue()


def pacote_manual(payload, *, magic=lsb.MAGIC, tamanho=None, digest=None):
    prefixo = magic + struct.pack('>I', len(payload) if tamanho is None else tamanho)
    return prefixo + (sha256(prefixo + payload).digest() if digest is None else digest) + payload


def escrever_pacote(pacote, size=(64, 64)):
    """Escritor independente (pixels/tuplas), para não espelhar o algoritmo."""
    imagem = Image.new('RGB', size, (122, 170, 230))
    pixels = imagem.load()
    bits = ''.join(format(byte, '08b') for byte in pacote)
    for indice, bit in enumerate(bits):
        posicao, canal = divmod(indice, 3)
        x, y = posicao % size[0], posicao // size[0]
        rgb = list(pixels[x, y])
        rgb[canal] = rgb[canal] - rgb[canal] % 2 + int(bit)
        pixels[x, y] = tuple(rgb)
    return imagem


class EsteganografiaTests(SimpleTestCase):
    def assertCodigo(self, codigo, funcao, *args):
        with self.assertRaises(lsb.ErroEsteganografia) as capturado:
            funcao(*args)
        self.assertEqual(capturado.exception.codigo, codigo)

    def test_roundtrip_utf8_multilinha_com_zeros_e_delimitadores(self):
        texto = 'Cifrado: \x00fim\x00\nAção ☕ 漢字 🔐\r\n:::fim:::'
        original = Image.new('RGB', (80, 60), (120, 177, 230))
        antes = original.tobytes()
        resultado = lsb.ocultar_texto(original, texto)
        recuperada = lsb.carregar_imagem(resultado.png)
        self.assertEqual(lsb.extrair_texto(recuperada), texto)
        self.assertEqual(original.tobytes(), antes)
        self.assertEqual(recuperada.size, original.size)
        self.assertEqual(resultado.png[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual(resultado.payload_bytes, len(texto.encode('utf-8')))
        self.assertEqual(resultado.utilizados_bits, (lsb.TAMANHO_CABECALHO + resultado.payload_bytes) * 8)
        self.assertEqual(resultado.capacidade_bytes, 80 * 60 * 3 // 8 - 44)
        self.assertEqual((resultado.largura, resultado.altura), original.size)

    def test_formato_pode_ser_extraido_de_escritor_independente(self):
        imagem = escrever_pacote(pacote_manual('texto externo ☕'.encode()))
        self.assertEqual(lsb.extrair_texto(imagem), 'texto externo ☕')

    def test_cabecalho_e_ordem_de_bits_sao_interoperaveis(self):
        resultado = lsb.ocultar_texto(Image.new('RGB', (32, 32)), 'A')
        imagem = Image.open(BytesIO(resultado.png))
        bits = ''.join(str(canal % 2) for pixel in imagem.getdata() for canal in pixel)
        esperado = pacote_manual(b'A')
        recuperado = bytes(int(bits[i:i + 8], 2) for i in range(0, len(esperado) * 8, 8))
        self.assertEqual(recuperado, esperado)

    def test_capacidade_exata_aceita_e_um_byte_a_mais_rejeita(self):
        imagem = Image.new('RGB', (16, 16))
        capacidade = lsb.capacidade_imagem(imagem)
        self.assertEqual(capacidade, 52)
        resultado = lsb.ocultar_texto(imagem, 'x' * capacidade)
        self.assertEqual(lsb.extrair_texto(lsb.carregar_imagem(resultado.png)), 'x' * capacidade)
        self.assertCodigo('capacidade_excedida', lsb.ocultar_texto, imagem, 'x' * (capacidade + 1))

    def test_limite_conta_bytes_utf8(self):
        imagem = Image.new('RGB', (16, 16))
        self.assertEqual(lsb.capacidade_imagem(imagem), 52)
        lsb.ocultar_texto(imagem, 'é' * 26)
        self.assertCodigo('capacidade_excedida', lsb.ocultar_texto, imagem, 'é' * 27)

    def test_limite_exato_com_sobras_de_bits_e_fronteiras_rgb_rgba(self):
        for modo in ('RGB', 'RGBA'):
            for dimensoes in ((1, 120), (1, 121), (17, 13), (19, 27)):
                with self.subTest(modo=modo, dimensoes=dimensoes):
                    imagem = Image.new(modo, dimensoes)
                    texto = 'x' * lsb.capacidade_imagem(imagem)
                    resultado = lsb.ocultar_texto(imagem, texto)
                    self.assertEqual(lsb.extrair_texto(lsb.carregar_imagem(resultado.png)), texto)

    def test_imagem_menor_que_cabecalho(self):
        imagem = Image.new('RGB', (8, 8))
        self.assertEqual(lsb.capacidade_imagem(imagem), 0)
        self.assertCodigo('capacidade_excedida', lsb.ocultar_texto, imagem, 'a')
        self.assertCodigo('sem_dados', lsb.extrair_texto, imagem)

    def test_cabecalho_sem_payload_nao_e_aceito(self):
        self.assertCodigo('tamanho_invalido', lsb.extrair_texto, escrever_pacote(pacote_manual(b'')))

    def test_texto_vazio_invalido_ou_surrogate_rejeitado(self):
        imagem = Image.new('RGB', (32, 32))
        for texto in ('', None, b'bytes', '\ud800'):
            with self.subTest(tipo=type(texto).__name__):
                self.assertCodigo('texto_invalido', lsb.ocultar_texto, imagem, texto)

    def test_magic_e_versao_incompativeis(self):
        for magic in (b'xxxxxxxx', b'APLSB002'):
            with self.subTest(magic=magic):
                self.assertCodigo('sem_dados', lsb.extrair_texto,
                                  escrever_pacote(pacote_manual(b'x', magic=magic)))

    def test_sem_dados_ocultos(self):
        self.assertCodigo('sem_dados', lsb.extrair_texto, Image.new('RGB', (64, 64)))

    def test_tamanho_forjado_validado_antes_de_alocar_payload(self):
        for tamanho in (0, 0xFFFFFFFF):
            with self.subTest(tamanho=tamanho):
                self.assertCodigo('tamanho_invalido', lsb.extrair_texto,
                                  escrever_pacote(pacote_manual(b'x', tamanho=tamanho)))

    def test_checksum_corrompido(self):
        self.assertCodigo('integridade_invalida', lsb.extrair_texto,
                          escrever_pacote(pacote_manual(b'x', digest=b'\0' * 32)))

    def test_checksum_tambem_protege_comprimento(self):
        pacote = bytearray(pacote_manual(b'abcd'))
        pacote[11] = 3
        self.assertCodigo('integridade_invalida', lsb.extrair_texto, escrever_pacote(pacote))

    def test_um_bit_alterado_no_payload_e_detectado(self):
        imagem = escrever_pacote(pacote_manual(b'abc'))
        pixel, canal = divmod(lsb.TAMANHO_CABECALHO * 8, 3)
        x, y = pixel % imagem.width, pixel // imagem.width
        rgb = list(imagem.getpixel((x, y)))
        rgb[canal] ^= 1
        imagem.putpixel((x, y), tuple(rgb))
        self.assertCodigo('integridade_invalida', lsb.extrair_texto, imagem)

    def test_utf8_invalido_mesmo_com_checksum_correto(self):
        self.assertCodigo('texto_invalido', lsb.extrair_texto,
                          escrever_pacote(pacote_manual(b'\xff\xfe')))

    def test_alpha_integro_limite_delta_mse_psnr_e_bits_nao_usados(self):
        for modo in ('RGB', 'RGBA'):
            with self.subTest(modo=modo):
                original = Image.new(modo, (64, 32))
                if modo == 'RGBA':
                    # Inclui pixels inteiramente transparentes, parciais e opacos.
                    original.putdata([(x % 256, (x * 17) % 256, (x * 31) % 256, x % 256)
                                      for x in range(64 * 32)])
                resultado = lsb.ocultar_texto(original, 'abc123' * 70)
                modificada = lsb.carregar_imagem(resultado.png)
                delta = ImageChops.difference(original.convert('RGB'), modificada.convert('RGB'))
                self.assertTrue(all(maximo <= 1 for minimo, maximo in delta.getextrema()))
                self.assertLessEqual(resultado.mse, 1)
                self.assertGreaterEqual(resultado.psnr, 10 * math.log10(255 ** 2))
                self.assertEqual(lsb.calcular_metricas(original, modificada), (resultado.mse, resultado.psnr))
                self.assertEqual(lsb.extrair_texto(modificada), 'abc123' * 70)
                if modo == 'RGBA':
                    self.assertEqual(original.getchannel('A').tobytes(), modificada.getchannel('A').tobytes())
                antes = original.convert('RGB').tobytes()
                depois = modificada.convert('RGB').tobytes()
                self.assertEqual(antes[resultado.utilizados_bits:], depois[resultado.utilizados_bits:])

    def test_metricas_conhecidas_e_imagens_identicas(self):
        original = Image.new('RGB', (2, 1), (0, 0, 0))
        modificada = Image.new('RGB', (2, 1), (1, 1, 1))
        self.assertEqual(lsb.calcular_metricas(original, modificada), (1, 10 * math.log10(255 ** 2)))
        self.assertEqual(lsb.calcular_metricas(original, original), (0, math.inf))
        modificada.putpixel((0, 0), (0, 0, 0))
        self.assertEqual(lsb.calcular_metricas(original, modificada)[0], 0.5)

    def test_metricas_recusam_dimensoes_distintas(self):
        self.assertCodigo('dimensoes_diferentes', lsb.calcular_metricas,
                          Image.new('RGB', (2, 2)), Image.new('RGB', (3, 2)))

    def test_api_nucleo_requer_imagem_normalizada(self):
        self.assertCodigo('imagem_invalida', lsb.capacidade_imagem, b'png')
        self.assertCodigo('modo_invalido', lsb.capacidade_imagem, Image.new('P', (8, 8)))

    def test_png_resultante_precisa_caber_no_limite_de_reenvio(self):
        with mock.patch.object(lsb, 'MAX_UPLOAD_BYTES', 10):
            self.assertCodigo('limite_saida', lsb.ocultar_texto, Image.new('RGB', (32, 32)), 'dados')


class ValidacaoImagemTests(SimpleTestCase):
    def assertCodigo(self, codigo, arquivo):
        with self.assertRaises(lsb.ErroEsteganografia) as capturado:
            lsb.carregar_imagem(arquivo)
        self.assertEqual(capturado.exception.codigo, codigo)

    def test_formatos_permitidos_decodificados_por_conteudo(self):
        for formato in ('PNG', 'JPEG', 'BMP', 'WEBP'):
            with self.subTest(formato=formato):
                dados = imagem_bytes(Image.new('RGB', (32, 24), (123, 76, 45)), formato)
                imagem = lsb.carregar_imagem(BytesIO(dados))
                self.assertEqual(imagem.mode, 'RGB')
                self.assertEqual(imagem.size, (32, 24))
                resultado = lsb.ocultar_texto(imagem, 'teste')
                self.assertEqual(lsb.extrair_texto(lsb.carregar_imagem(resultado.png)), 'teste')

    def test_grayscale_palette_e_transparencia_preservada(self):
        for modo in ('1', 'L', 'LA', 'P', 'RGB', 'RGBA'):
            with self.subTest(modo=modo):
                original = Image.new(modo, (24, 24))
                if modo == 'P':
                    original.putpalette([value for value in range(256) for _ in range(3)])
                    original.info['transparency'] = 0
                if modo == 'RGB':
                    original.info['transparency'] = (0, 0, 0)
                carregada = lsb.carregar_imagem(imagem_bytes(original))
                self.assertIn(carregada.mode, ('RGB', 'RGBA'))
                esperado = original.convert(carregada.mode)
                self.assertEqual(carregada.tobytes(), esperado.tobytes())
                if modo in ('LA', 'P', 'RGB', 'RGBA'):
                    self.assertEqual(carregada.mode, 'RGBA')

    def test_orientacao_exif_perfil_e_dpi_acompanham_png_sem_rotacao(self):
        original = Image.new('RGB', (32, 20), (12, 56, 201))
        exif = Image.Exif()
        exif[274] = 6  # visualmente rotacionada; pixels devem manter a ordem.
        dados = imagem_bytes(original, exif=exif, icc_profile=b'perfil-de-teste', dpi=(150, 150))
        carregada = lsb.carregar_imagem(dados)
        self.assertEqual(carregada.size, (32, 20))
        resultado = lsb.ocultar_texto(carregada, 'com orientação')
        png = Image.open(BytesIO(resultado.png))
        self.assertEqual(png.getexif()[274], 6)
        self.assertEqual(png.info['icc_profile'], b'perfil-de-teste')
        self.assertAlmostEqual(png.info['dpi'][0], 150, places=1)
        self.assertEqual(lsb.extrair_texto(lsb.carregar_imagem(resultado.png)), 'com orientação')

    def test_stream_tem_posicao_restaurada_e_imagem_independente(self):
        arquivo = BytesIO(imagem_bytes(Image.new('RGB', (20, 20), (5, 10, 15))))
        arquivo.seek(3)
        imagem = lsb.carregar_imagem(arquivo)
        self.assertEqual(arquivo.tell(), 3)
        arquivo.close()
        self.assertEqual(imagem.getpixel((0, 0)), (5, 10, 15))

    def test_png_preserva_gamma_srgb_e_cromaticidade(self):
        cores = PngImagePlugin.PngInfo()
        cores.add(b'gAMA', struct.pack('>I', 45455))
        cores.add(b'sRGB', b'\0')
        cromaticidade = (31270, 32900, 64000, 33000, 30000, 60000, 15000, 6000)
        cores.add(b'cHRM', struct.pack('>8I', *cromaticidade))
        dados = imagem_bytes(Image.new('RGB', (32, 32)), pnginfo=cores)
        original = lsb.carregar_imagem(dados)
        resultado = lsb.ocultar_texto(original, 'cores preservadas')
        imagem = lsb.carregar_imagem(resultado.png)
        self.assertEqual(imagem.info['gamma'], 0.45455)
        self.assertEqual(imagem.info['srgb'], 0)
        self.assertEqual(imagem.info['chromaticity'], tuple(v / 100000 for v in cromaticidade))
        self.assertEqual(lsb.extrair_texto(imagem), 'cores preservadas')

    def test_arquivo_invalido_vazio_ou_truncado(self):
        png = imagem_bytes(Image.new('RGB', (32, 32)))
        for dados in (b'', b'arquivo fingindo ser png', png[:40], png[:-12], None):
            with self.subTest(tamanho=len(dados) if dados is not None else None):
                self.assertCodigo('imagem_invalida', dados)

    def test_formato_nao_suportado(self):
        self.assertCodigo('formato_invalido', imagem_bytes(Image.new('RGB', (32, 32)), 'TIFF'))

    def test_modos_que_exigiriam_conversao_destrutiva_sao_rejeitados(self):
        for modo, formato in (('I;16', 'PNG'), ('CMYK', 'JPEG')):
            with self.subTest(modo=modo):
                self.assertCodigo('modo_invalido', imagem_bytes(Image.new(modo, (32, 32)), formato))

    def test_png_rgb16_rejeitado_mesmo_quando_pillow_expoe_modo_rgb(self):
        def chunk(tipo, conteudo):
            return (struct.pack('>I', len(conteudo)) + tipo + conteudo
                    + struct.pack('>I', binascii.crc32(tipo + conteudo)))

        cabecalho = struct.pack('>IIBBBBB', 32, 32, 16, 2, 0, 0, 0)
        linhas = (b'\0' + b'\x12\x34\x56\x78\x9a\xbc' * 32) * 32
        png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', cabecalho)
               + chunk(b'IDAT', zlib.compress(linhas)) + chunk(b'IEND', b''))
        with Image.open(BytesIO(png)) as imagem:
            imagem.load()
            self.assertEqual(imagem.mode, 'RGB')
        self.assertCodigo('modo_invalido', png)

    def test_png_animado_rejeitado(self):
        dados = imagem_bytes(Image.new('RGB', (16, 16)), save_all=True,
                             append_images=[Image.new('RGB', (16, 16), 'white')], duration=100, loop=0)
        self.assertCodigo('imagem_animada', dados)

    def test_limite_upload_lido_com_teto(self):
        dados = imagem_bytes(Image.new('RGB', (32, 32)))
        with mock.patch.object(lsb, 'MAX_UPLOAD_BYTES', 10):
            self.assertCodigo('limite_upload', dados)
            arquivo = BytesIO(dados)
            self.assertCodigo('limite_upload', arquivo)
            self.assertEqual(arquivo.tell(), 0)

    def test_limite_pixels_antes_de_load(self):
        dados = imagem_bytes(Image.new('RGB', (32, 32)))
        with mock.patch.object(lsb, 'MAX_PIXELS', 100):
            self.assertCodigo('limite_pixels', dados)

    def test_decompression_bomb_aviso_tratado_como_erro(self):
        dados = imagem_bytes(Image.new('RGB', (32, 32)))
        with mock.patch.object(Image, 'MAX_IMAGE_PIXELS', 800):
            self.assertCodigo('limite_pixels', dados)

    def test_decompression_bomb_erro_tratado(self):
        dados = imagem_bytes(Image.new('RGB', (32, 32)))
        with mock.patch.object(Image, 'MAX_IMAGE_PIXELS', 100):
            self.assertCodigo('limite_pixels', dados)
