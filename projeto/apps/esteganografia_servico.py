"""Integração da cifra existente, contêiner LSB e auditoria sem segredos.

A cifra didática permanece intacta. Um envelope autenticado independente
permite verificar a chave antes de chamar seu decifrar(). Nenhuma chave ou
mensagem é persistida por este serviço.
"""
import base64
import binascii
import hashlib
import hmac
import json
import math
from contextlib import contextmanager

from . import mensageria_cripto as cripto
from .esteganografia import (
    ErroEsteganografia, TAMANHO_CABECALHO, capacidade_imagem,
    carregar_imagem, extrair_texto, ocultar_texto,
)
from .eventos import agora_ms, registrar_evento

MAX_MENSAGEM_BYTES = 65_536
_DOMINIO = b'aponte-esteganografia-auth-v1'


def _validar_chave(chave):
    try:
        dados = base64.b64decode(chave.encode('ascii'), altchars=b'-_', validate=True)
        if len(dados) != cripto.TAMANHO_CHAVE:
            raise ValueError
        if base64.urlsafe_b64encode(dados).decode('ascii') != chave:
            raise ValueError
        return dados
    except (ValueError, AttributeError, UnicodeError, binascii.Error):
        raise ErroEsteganografia(
            'chave_invalida',
            f'Informe uma chave válida da mensageria: {cripto.TAMANHO_CHAVE} bytes em Base64 URL-safe '
            f'({4 * ((cripto.TAMANHO_CHAVE + 2) // 3)} caracteres).',
        ) from None


def _autenticacao(cifrado, chave_bytes):
    # Separação de domínio: a chave do MAC é derivada para este envelope.
    chave_mac = hmac.new(chave_bytes, _DOMINIO, hashlib.sha256).digest()
    return hmac.new(chave_mac, b'APSTEG1\0' + cifrado.encode('ascii'), hashlib.sha256).hexdigest()


def _envelope(cifrado, autenticacao):
    return json.dumps({'v': 1, 'c': cifrado, 'h': autenticacao}, separators=(',', ':'))


def _tamanho_envelope(bytes_mensagem):
    # O tamanho do texto cifrado vem da própria cifra (IV + blocos + tag).
    return len(_envelope('', '0' * 64)) + cripto.tamanho_cifrado(bytes_mensagem)


def _metricas(imagem, payload_bytes=0):
    utilizados = (TAMANHO_CABECALHO + payload_bytes) * 8 if payload_bytes else 0
    total_bits = imagem.width * imagem.height * 3
    return {
        'largura': imagem.width, 'altura': imagem.height,
        'capacidade_bytes': capacidade_imagem(imagem),
        'payload_bytes': payload_bytes, 'utilizados_bits': utilizados,
        'capacidade_utilizada_percentual': round(100 * utilizados / total_bits, 4),
    }


@contextmanager
def _auditar(operacao, usuario, ip):
    inicio = agora_ms()
    detalhes = {'operacao': operacao}
    try:
        yield detalhes
    except Exception as exc:
        # Nunca serializar a exceção: uma falha de biblioteca pode conter dados.
        detalhes.update(resultado='falha', motivo=(
            exc.codigo if isinstance(exc, ErroEsteganografia) else 'erro_interno'
        ))
        registrar_evento(
            'esteganografia', usuario=usuario, ip=ip, origem='esteganografia_servico',
            sucesso=False, severidade='alerta', detalhes=detalhes,
            duracao_ms=round(agora_ms() - inicio, 3),
        )
        raise
    else:
        detalhes['resultado'] = 'sucesso'
        registrar_evento(
            'esteganografia', usuario=usuario, ip=ip, origem='esteganografia_servico',
            sucesso=True, detalhes=detalhes,
            duracao_ms=round(agora_ms() - inicio, 3),
        )


def ocultar_mensagem(arquivo, mensagem, chave='', *, usuario='', ip=None):
    """Cifra o texto sem normalizá-lo e devolve PNG/chave só em memória."""
    with _auditar('ocultacao', usuario, ip) as detalhes:
        imagem = carregar_imagem(arquivo)
        try:
            detalhes.update(_metricas(imagem))
            if not isinstance(mensagem, str) or not mensagem:
                raise ErroEsteganografia('mensagem_vazia', 'Insira uma mensagem para ocultar.')
            try:
                tamanho = len(mensagem.encode('utf-8'))
            except UnicodeEncodeError:
                raise ErroEsteganografia('mensagem_invalida', 'A mensagem deve conter texto UTF-8 válido.') from None
            if tamanho > MAX_MENSAGEM_BYTES:
                raise ErroEsteganografia('mensagem_grande', 'A mensagem excede o limite de 65.536 bytes UTF-8.')
            necessario = _tamanho_envelope(tamanho)
            detalhes['payload_solicitado_bytes'] = necessario
            if necessario > detalhes['capacidade_bytes']:
                raise ErroEsteganografia(
                    'capacidade_insuficiente',
                    f'A imagem comporta {detalhes["capacidade_bytes"]} bytes; '
                    f'a mensagem cifrada com autenticação requer {necessario} bytes. Escolha uma imagem maior.',
                )
            chave = chave.strip() if isinstance(chave, str) else chave
            if chave == '':
                chave = cripto.gerar_chave()
            chave_bytes = _validar_chave(chave)
            cifrado = cripto.cifrar(mensagem, chave, usuario=usuario, ip=ip)
            envelope = _envelope(cifrado, _autenticacao(cifrado, chave_bytes))
            resultado = ocultar_texto(imagem, envelope)
            metricas = _metricas(imagem, resultado.payload_bytes)
            metricas.update(mse=resultado.mse, psnr=(
                resultado.psnr if math.isfinite(resultado.psnr) else None
            ))
            detalhes.update(metricas)
            return {
                'imagem_png': resultado.png, 'chave': chave,
                'texto_cifrado': cifrado, 'metricas': metricas,
            }
        finally:
            imagem.close()


def _ler_envelope(payload):
    try:
        if len(payload) > _tamanho_envelope(MAX_MENSAGEM_BYTES):
            raise ValueError
        envelope = json.loads(payload)
        if not isinstance(envelope, dict) or set(envelope) != {'v', 'c', 'h'}:
            raise ValueError
        if type(envelope['v']) is not int or envelope['v'] != 1:
            raise ValueError
        cifrado, assinatura = envelope['c'], envelope['h']
        if not isinstance(cifrado, str) or not isinstance(assinatura, str):
            raise ValueError
        bruto = base64.b64decode(cifrado.encode('ascii'), altchars=b'-_', validate=True)
        if len(bruto) < 2 * cripto.TAMANHO_BLOCO or len(bruto) % cripto.TAMANHO_BLOCO:
            raise ValueError
        if base64.urlsafe_b64encode(bruto).decode('ascii') != cifrado:
            raise ValueError
        if len(assinatura) != 64 or any(c not in '0123456789abcdef' for c in assinatura):
            raise ValueError
        return cifrado, assinatura
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        raise ErroEsteganografia(
            'envelope_invalido', 'O conteúdo oculto não é uma mensagem cifrada compatível com este sistema.'
        ) from None


def extrair_mensagem(arquivo, chave='', *, usuario='', ip=None):
    """Extrai o cifrado; autentica e decifra somente quando há uma chave."""
    with _auditar('extracao', usuario, ip) as detalhes:
        imagem = carregar_imagem(arquivo)
        try:
            detalhes.update(_metricas(imagem))
            payload = extrair_texto(imagem)
            metricas = _metricas(imagem, len(payload.encode('utf-8')))
            detalhes.update(metricas)
            cifrado, assinatura = _ler_envelope(payload)
            mensagem = None
            chave = chave.strip() if isinstance(chave, str) else chave
            if chave != '':
                chave_bytes = _validar_chave(chave)
                if not hmac.compare_digest(_autenticacao(cifrado, chave_bytes), assinatura):
                    registrar_evento(
                        'falha_decifragem', usuario=usuario, ip=ip,
                        origem='esteganografia_servico',
                        detalhes={'motivo': 'autenticacao_invalida'},
                    )
                    raise ErroEsteganografia(
                        'autenticacao_invalida', 'Chave incorreta ou autenticação da mensagem inválida.'
                    )
                try:
                    mensagem = cripto.decifrar(cifrado, chave, usuario=usuario, ip=ip)
                except (ValueError, UnicodeError, IndexError):
                    raise ErroEsteganografia('falha_decifragem', 'Não foi possível descriptografar a mensagem.') from None
            detalhes['descriptografada'] = mensagem is not None
            return {'texto_cifrado': cifrado, 'mensagem': mensagem, 'metricas': metricas}
        finally:
            imagem.close()
