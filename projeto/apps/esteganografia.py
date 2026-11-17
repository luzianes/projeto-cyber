"""Contêiner LSB versionado para textos UTF-8 em imagens RGB/RGBA.

Não cifra nem decifra: recebe o texto produzido pela camada de criptografia.
O cabeçalho contém magic/versão (8 bytes), comprimento big-endian (4 bytes)
e SHA-256 do prefixo + payload (32 bytes). Cada byte é escrito do bit mais
significativo para o menos significativo, nos canais R, G, B, linha a linha.
O canal alpha nunca transporta dados. O checksum detecta corrupção; a
autenticação com a chave pertence à camada de integração.
"""

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import hmac
import math
import struct
import warnings

from PIL import Image, ImageChops, PngImagePlugin, UnidentifiedImageError


MAGIC = b'APLSB001'
TAMANHO_CABECALHO = len(MAGIC) + 4 + 32
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_PIXELS = 8_000_000
FORMATOS_PERMITIDOS = frozenset({'PNG', 'JPEG', 'BMP', 'WEBP'})
_METADADOS_PNG = ('icc_profile', 'exif', 'dpi')
_METADADOS_COR_PNG = ('gamma', 'srgb', 'chromaticity')


class ErroEsteganografia(ValueError):
    """Falha esperada, com código estável e mensagem sem conteúdo secreto."""

    def __init__(self, codigo, mensagem):
        self.codigo = codigo
        super().__init__(mensagem)


@dataclass(frozen=True)
class ResultadoOcultacao:
    png: bytes
    capacidade_bytes: int
    payload_bytes: int
    utilizados_bits: int
    mse: float
    psnr: float
    largura: int
    altura: int


def _validar_dimensoes(imagem):
    if imagem.width <= 0 or imagem.height <= 0 or imagem.width * imagem.height > MAX_PIXELS:
        raise ErroEsteganografia(
            'limite_pixels', f'A imagem deve ter até {MAX_PIXELS:,} pixels.'
        )


def _validar_imagem(imagem):
    if not isinstance(imagem, Image.Image):
        raise ErroEsteganografia('imagem_invalida', 'Envie uma imagem válida.')
    _validar_dimensoes(imagem)
    if imagem.mode not in ('RGB', 'RGBA'):
        raise ErroEsteganografia(
            'modo_invalido', 'Carregue a imagem em RGB ou RGBA antes da operação.'
        )


def carregar_imagem(arquivo):
    """Valida um upload/bytes e devolve imagem independente, RGB ou RGBA.

Extensão e MIME declarados pelo cliente não são usados para validar o
conteúdo. Limites são verificados antes de descomprimir os pixels. Não há
rotação automática: ela destruiria a ordem dos bits durante a extração.
Perfis de cor, gamma, DPI e EXIF (incluindo orientação) acompanham a saída PNG.
"""
    posicao = None
    try:
        if isinstance(arquivo, (bytes, bytearray, memoryview)):
            if len(arquivo) > MAX_UPLOAD_BYTES:
                raise ErroEsteganografia('limite_upload', 'A imagem excede o limite de 16 MiB.')
            dados = bytes(arquivo)
        else:
            if arquivo is None or not hasattr(arquivo, 'read'):
                raise ErroEsteganografia('imagem_invalida', 'Selecione uma imagem válida.')
            posicao = arquivo.tell()
            arquivo.seek(0)
            dados = arquivo.read(MAX_UPLOAD_BYTES + 1)
        if len(dados) > MAX_UPLOAD_BYTES:
            raise ErroEsteganografia('limite_upload', 'A imagem excede o limite de 16 MiB.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(BytesIO(dados)) as original:
                if original.format not in FORMATOS_PERMITIDOS:
                    raise ErroEsteganografia(
                        'formato_invalido', 'Use uma imagem PNG, JPEG, BMP ou WebP.'
                    )
                _validar_dimensoes(original)
                # O decoder do Pillow expõe PNG RGB16 como RGB8. Consulte
                # também a profundidade do IHDR para evitar perda silenciosa.
                png_alta_profundidade = original.format == 'PNG' and dados[24] > 8
                if png_alta_profundidade or original.mode not in ('1', 'L', 'LA', 'P', 'RGB', 'RGBA'):
                    raise ErroEsteganografia(
                        'modo_invalido',
                        'Use uma imagem RGB, tons de cinza de 8 bits ou paleta; converta imagens CMYK ou de alta profundidade antes do envio.'
                    )
                if getattr(original, 'is_animated', False) or getattr(original, 'n_frames', 1) != 1:
                    raise ErroEsteganografia('imagem_animada', 'Use uma imagem estática, sem animação.')
                original.verify()
            # verify() invalida o decoder; reabrir também permite testar a carga completa.
            with Image.open(BytesIO(dados)) as original:
                original.load()
                tem_alpha = 'A' in original.getbands() or 'transparency' in original.info
                imagem = original.convert('RGBA' if tem_alpha else 'RGB')
                imagem.info = {k: original.info[k] for k in _METADADOS_PNG + _METADADOS_COR_PNG
                               if k in original.info}
                return imagem
    except ErroEsteganografia:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ErroEsteganografia('limite_pixels', 'A imagem excede o limite seguro de pixels.') from None
    except (UnidentifiedImageError, OSError, ValueError, TypeError, SyntaxError, EOFError, struct.error):
        raise ErroEsteganografia('imagem_invalida', 'Não foi possível ler a imagem. O arquivo é inválido ou está corrompido.') from None
    finally:
        if posicao is not None:
            try:
                arquivo.seek(posicao)
            except (OSError, ValueError):
                pass  # Não substitui o erro de validação se o stream foi fechado.


def capacidade_imagem(imagem):
    """Capacidade útil em bytes, descontando os 44 bytes do cabeçalho."""
    _validar_imagem(imagem)
    return max(0, imagem.width * imagem.height * 3 // 8 - TAMANHO_CABECALHO)


def calcular_metricas(original, modificada):
    """MSE e PSNR sobre todos os canais RGB de 8 bits (alpha excluído)."""
    _validar_imagem(original)
    _validar_imagem(modificada)
    if original.size != modificada.size:
        raise ErroEsteganografia('dimensoes_diferentes', 'As imagens devem ter as mesmas dimensões.')
    diferenca = ImageChops.difference(original.convert('RGB'), modificada.convert('RGB'))
    soma_quadrados = sum((indice % 256) ** 2 * quantidade
                        for indice, quantidade in enumerate(diferenca.histogram()))
    mse = soma_quadrados / (original.width * original.height * 3)
    psnr = math.inf if mse == 0 else 10 * math.log10(255 ** 2 / mse)
    return mse, psnr


def ocultar_texto(imagem, texto_cifrado):
    """Oculta exatamente a string recebida e retorna PNG + métricas.

Cada amostra RGB varia no máximo uma unidade. O objeto original permanece
intacto, assim como dimensões e alpha. O limite considera bytes UTF-8,
incluindo o cabeçalho; caracteres multibyte não são contados como um byte.
"""
    capacidade = capacidade_imagem(imagem)
    if not isinstance(texto_cifrado, str) or not texto_cifrado:
        raise ErroEsteganografia('texto_invalido', 'O texto cifrado não pode ser vazio.')
    try:
        payload = texto_cifrado.encode('utf-8')
    except UnicodeEncodeError:
        raise ErroEsteganografia('texto_invalido', 'O texto cifrado deve ser UTF-8 válido.') from None
    if len(payload) > capacidade:
        raise ErroEsteganografia(
            'capacidade_excedida',
            f'A imagem comporta {capacidade} bytes, mas o conteúdo requer {len(payload)} bytes.'
        )
    prefixo = MAGIC + struct.pack('>I', len(payload))
    pacote = prefixo + sha256(prefixo + payload).digest() + payload
    pixels = bytearray(imagem.tobytes())
    canais = len(imagem.getbands())
    indice = 0
    for byte in pacote:
        for deslocamento in range(7, -1, -1):
            pixels[indice] = (pixels[indice] & 0xFE) | ((byte >> deslocamento) & 1)
            indice += 1
            if canais == 4 and indice % 4 == 3:
                indice += 1
    modificada = Image.frombytes(imagem.mode, imagem.size, bytes(pixels))
    mse, psnr = calcular_metricas(imagem, modificada)
    saida = BytesIO()
    metadados = {k: imagem.info[k] for k in _METADADOS_PNG if k in imagem.info}
    cores = PngImagePlugin.PngInfo()
    if 'gamma' in imagem.info:
        cores.add(b'gAMA', struct.pack('>I', round(imagem.info['gamma'] * 100000)))
    if 'srgb' in imagem.info:
        cores.add(b'sRGB', bytes([imagem.info['srgb']]))
    if 'chromaticity' in imagem.info and len(imagem.info['chromaticity']) == 8:
        cores.add(b'cHRM', struct.pack('>8I', *(round(v * 100000) for v in imagem.info['chromaticity'])))
    modificada.save(saida, format='PNG', pnginfo=cores, **metadados)
    png = saida.getvalue()
    if len(png) > MAX_UPLOAD_BYTES:
        raise ErroEsteganografia(
            'limite_saida',
            'O PNG resultante excede 16 MiB e não poderia ser enviado para extração. Escolha uma imagem menor.'
        )
    return ResultadoOcultacao(
        png=png, capacidade_bytes=capacidade, payload_bytes=len(payload),
        utilizados_bits=len(pacote) * 8, mse=mse, psnr=psnr,
        largura=imagem.width, altura=imagem.height,
    )


def _ler_bytes(pixels, canais, quantidade, inicio_bits=0):
    saida = bytearray(quantidade)
    indice = inicio_bits if canais == 3 else inicio_bits // 3 * 4 + inicio_bits % 3
    for posicao in range(quantidade):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | (pixels[indice] & 1)
            indice += 1
            if canais == 4 and indice % 4 == 3:
                indice += 1
        saida[posicao] = byte
    return bytes(saida)


def extrair_texto(imagem):
    """Extrai UTF-8 somente após validar versão, comprimento e checksum."""
    capacidade = capacidade_imagem(imagem)
    if imagem.width * imagem.height * 3 < TAMANHO_CABECALHO * 8:
        raise ErroEsteganografia('sem_dados', 'A imagem não contém um cabeçalho LSB completo.')
    canais = len(imagem.getbands())
    pixels = imagem.tobytes()
    cabecalho = _ler_bytes(pixels, canais, TAMANHO_CABECALHO)
    if cabecalho[:len(MAGIC)] != MAGIC:
        raise ErroEsteganografia('sem_dados', 'Dados LSB ausentes, corrompidos ou de versão incompatível.')
    tamanho = struct.unpack('>I', cabecalho[len(MAGIC):len(MAGIC) + 4])[0]
    if tamanho == 0 or tamanho > capacidade:
        raise ErroEsteganografia('tamanho_invalido', 'O tamanho declarado dos dados ocultos é inválido.')
    payload = _ler_bytes(pixels, canais, tamanho, TAMANHO_CABECALHO * 8)
    esperado = sha256(cabecalho[:len(MAGIC) + 4] + payload).digest()
    if not hmac.compare_digest(esperado, cabecalho[len(MAGIC) + 4:]):
        raise ErroEsteganografia('integridade_invalida', 'A integridade dos dados ocultos não confere. A imagem pode ter sido alterada.')
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        raise ErroEsteganografia('texto_invalido', 'Os dados ocultos não contêm texto UTF-8 válido.') from None
