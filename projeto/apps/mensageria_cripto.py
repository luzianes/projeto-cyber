"""
Cifra simétrica própria do Projeto 2, usada na mensageria privada
cliente -> cafeteria.

VERSÃO 2: corrigida a partir dos ataques da Pessoa 2 (docs/ATAQUES_CIFRA.md).
A v1 original continua em cifra_v1_legada.py, só para migrar mensagens
antigas e reproduzir os ataques do "antes".

DESENHO (rede de substituição-permutação no estilo do AES, simplificada):

  texto (utf-8) -> blocos de 16 bytes (padding PKCS7)
      -> encadeamento CBC com IV aleatório de 16 bytes
          -> para cada bloco, 10 rodadas de:
                 XOR com a sub-chave da rodada             (chave)
                 substituição byte a byte via S-box fixa   (confusão)
                 permutação da ordem dos bytes (P-box)     (difusão entre colunas)
                 mistura de colunas (MixColumns)           (difusão entre bytes)
             e um XOR final com uma 11ª sub-chave
      -> HMAC-SHA256 sobre IV + blocos (autenticação, "encrypt-then-MAC")
      -> base64(IV + blocos + tag), string pra caber no banco

Peças do requisito (Parte 2, slide 7): chave dinâmica (gerar_chave() sorteia
uma chave nova por mensagem), XOR, substituição, permutação e blocos.

O QUE OS ATAQUES ACHARAM NA V1 E O QUE MUDOU:

  v1                                              v2
  ----------------------------------------------  -------------------------------------------
  P-box só trocava bytes de lugar: cada byte      MixColumns: cada byte da coluna passa a
  cifrado dependia de 1 byte de entrada (6% de    depender dos 4; com a P-box, em 2 rodadas
  avalanche, cifra = 8 cifras de 1 byte)          1 byte de entrada afeta o bloco inteiro
  chave de 64 bits, recuperada em ~1 s byte a     chave de 128 bits; sem bytes independentes,
  byte com 24 bytes de texto conhecido            o ataque byte a byte não se aplica
  sub-chaves = rotações da chave                  sub-chaves derivadas por HMAC-SHA256
  4 rodadas, terminando em S-box pública          10 rodadas + XOR final com sub-chave
  sem autenticação: dava pra trocar "2 pessoas"   HMAC-SHA256 conferido ANTES de decifrar:
  por "9 pessoas" sem a chave                     qualquer alteração é rejeitada
  bloco de 8 bytes                                bloco de 16 bytes

S-box e P-box continuam fixas e públicas (como no AES): quem protege os dados
é só a chave. A S-box é a mesma da v1 (permutação sorteada com semente 42).

A chave de cada mensagem é guardada cifrada no banco (MensagemPrivada.chave é
um EncryptedCharField, protegido pela FIELD_ENCRYPTION_KEY, fora do banco).

Para atacar: `python manage.py rodar_ataques` (ver ataques_cripto.py).
"""
import base64
import binascii
import hashlib
import hmac
import logging
import os
import random

from .eventos import agora_ms, registrar_evento

logger = logging.getLogger('security')

VERSAO = 'v2'
TAMANHO_BLOCO = 16  # bytes
TAMANHO_CHAVE = 16  # bytes (128 bits)
NUM_RODADAS = 10
TAMANHO_TAG = 32    # HMAC-SHA256
_DOMINIO = b'aponte-mensageria-v2'


# --- S-box fixa (substituição) -----------------------------------------
# Permutação fixa e pública dos 256 valores de 1 byte (semente fixa).
def _gerar_sbox():
    valores = list(range(256))
    random.Random(42).shuffle(valores)
    return valores


_SBOX = _gerar_sbox()
_SBOX_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _SBOX_INV[_v] = _i


# --- P-box fixa (permutação dos bytes do bloco) -------------------------
# O bloco é visto como uma matriz 4x4 guardada coluna a coluna (byte i =
# linha i % 4, coluna i // 4) e a linha r gira r posições, como o ShiftRows
# do AES. Assim os 4 bytes de cada coluna vão para 4 colunas diferentes, e o
# MixColumns da rodada seguinte mistura bytes que vieram de colunas distintas.
_PBOX = [4 * ((i // 4 + i % 4) % 4) + i % 4 for i in range(TAMANHO_BLOCO)]
_PBOX_INV = [0] * TAMANHO_BLOCO
for _i, _v in enumerate(_PBOX):
    _PBOX_INV[_v] = _i


# --- Mistura de colunas (MixColumns, multiplicação em GF(2^8)) ----------
def _gmul(a, b):
    """Multiplicação no corpo GF(2^8) do AES (polinômio x^8+x^4+x^3+x+1)."""
    produto = 0
    while b:
        if b & 1:
            produto ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return produto


_MUL = {k: [_gmul(x, k) for x in range(256)] for k in (2, 3, 9, 11, 13, 14)}


def _misturar_colunas(bloco):
    """Cada byte de saída da coluna depende dos 4 bytes de entrada dela. A
    matriz é MDS: mudar 1 byte de entrada muda os 4 de saída."""
    m2, m3 = _MUL[2], _MUL[3]
    saida = bytearray(TAMANHO_BLOCO)
    for c in range(0, TAMANHO_BLOCO, 4):
        a0, a1, a2, a3 = bloco[c:c + 4]
        saida[c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        saida[c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        saida[c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        saida[c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
    return bytes(saida)


def _desmisturar_colunas(bloco):
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    saida = bytearray(TAMANHO_BLOCO)
    for c in range(0, TAMANHO_BLOCO, 4):
        a0, a1, a2, a3 = bloco[c:c + 4]
        saida[c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        saida[c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        saida[c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        saida[c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    return bytes(saida)


# --- chave ---------------------------------------------------------------
def gerar_chave():
    """Chave dinâmica: 16 bytes aleatórios novos a cada chamada (requisito:
    'não pode ser fixa'). Retorna como string base64 URL-safe."""
    return base64.urlsafe_b64encode(os.urandom(TAMANHO_CHAVE)).decode('ascii')


def _chave_bytes(chave):
    try:
        dados = base64.urlsafe_b64decode(chave.encode('ascii'))
    except (binascii.Error, UnicodeEncodeError, AttributeError):
        raise ValueError('chave inválida: não é base64') from None
    if len(dados) != TAMANHO_CHAVE:
        raise ValueError(f'chave inválida: esperados {TAMANHO_CHAVE} bytes, recebidos {len(dados)}')
    return dados


def _derivar(chave_bytes, rotulo):
    return hmac.new(chave_bytes, _DOMINIO + b'|' + rotulo, hashlib.sha256).digest()


def _subchaves(chave_bytes):
    """NUM_RODADAS + 1 sub-chaves de 16 bytes, derivadas da chave por
    HMAC-SHA256 com um rótulo por rodada. Diferente da v1 (rotações da mesma
    chave), descobrir uma sub-chave não revela as outras nem a chave."""
    return [_derivar(chave_bytes, b'rodada' + bytes([r]))[:TAMANHO_BLOCO]
            for r in range(NUM_RODADAS + 1)]


def _chave_mac(chave_bytes):
    """Chave do HMAC, separada das sub-chaves de cifragem."""
    return _derivar(chave_bytes, b'mac')


# --- rodadas ---------------------------------------------------------------
def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _substituir(bloco, tabela):
    return bytes(tabela[byte] for byte in bloco)


def _permutar(bloco, tabela):
    # saida[i] = entrada[tabela[i]]; com a tabela inversa, desfaz a permutação.
    return bytes(bloco[tabela[i]] for i in range(len(bloco)))


def _cifrar_bloco(bloco, subchaves):
    estado = bloco
    for sub in subchaves[:-1]:
        estado = _xor_bytes(estado, sub)
        estado = _substituir(estado, _SBOX)
        estado = _permutar(estado, _PBOX)
        estado = _misturar_colunas(estado)
    # XOR final: sem ele, a última rodada poderia ser desfeita por qualquer um
    # (S-box, P-box e MixColumns são públicas).
    return _xor_bytes(estado, subchaves[-1])


def _decifrar_bloco(bloco, subchaves):
    estado = _xor_bytes(bloco, subchaves[-1])
    for sub in reversed(subchaves[:-1]):
        estado = _desmisturar_colunas(estado)
        estado = _permutar(estado, _PBOX_INV)
        estado = _substituir(estado, _SBOX_INV)
        estado = _xor_bytes(estado, sub)
    return estado


# --- padding, modo CBC, autenticação ---------------------------------------
def _aplicar_padding(dados):
    """PKCS7: sempre adiciona de 1 a 16 bytes."""
    faltam = TAMANHO_BLOCO - (len(dados) % TAMANHO_BLOCO)
    return dados + bytes([faltam] * faltam)


def _remover_padding(dados):
    if not dados:
        raise ValueError('padding inválido: dados vazios')
    faltam = dados[-1]
    if faltam < 1 or faltam > TAMANHO_BLOCO or faltam > len(dados) \
            or dados[-faltam:] != bytes([faltam]) * faltam:
        raise ValueError('padding inválido')
    return dados[:-faltam]


def _cifrar_cbc(dados, subchaves, iv):
    """dados já com padding -> blocos cifrados (sem o IV). Cada bloco passa por
    XOR com o cifrado anterior antes das rodadas (o 1º, com o IV)."""
    saida, anterior = [], iv
    for i in range(0, len(dados), TAMANHO_BLOCO):
        anterior = _cifrar_bloco(_xor_bytes(dados[i:i + TAMANHO_BLOCO], anterior), subchaves)
        saida.append(anterior)
    return b''.join(saida)


def _tag(chave_bytes, iv, corpo):
    return hmac.new(_chave_mac(chave_bytes), _DOMINIO + iv + corpo, hashlib.sha256).digest()


def _decompor(texto_cifrado):
    """string base64 -> (iv, blocos cifrados, tag)."""
    try:
        bruto = base64.urlsafe_b64decode(texto_cifrado.encode('ascii'))
    except (binascii.Error, UnicodeEncodeError, AttributeError):
        raise ValueError('texto cifrado inválido: não é base64') from None
    corpo = len(bruto) - TAMANHO_BLOCO - TAMANHO_TAG
    if corpo < TAMANHO_BLOCO or corpo % TAMANHO_BLOCO:
        raise ValueError('texto cifrado com tamanho inválido')
    return bruto[:TAMANHO_BLOCO], bruto[TAMANHO_BLOCO:-TAMANHO_TAG], bruto[-TAMANHO_TAG:]


def tamanho_cifrado(bytes_texto):
    """Tamanho, em caracteres, da string que cifrar() devolve para um texto de
    `bytes_texto` bytes UTF-8 (usado pela esteganografia para checar a
    capacidade da imagem antes de cifrar)."""
    bruto = TAMANHO_BLOCO + (bytes_texto // TAMANHO_BLOCO + 1) * TAMANHO_BLOCO + TAMANHO_TAG
    return 4 * ((bruto + 2) // 3)


# --- API ------------------------------------------------------------------
def cifrar(texto, chave, usuario='', ip=None):
    """texto: str. chave: string base64 (de gerar_chave()).
    Retorna: string base64 com IV + blocos cifrados + tag HMAC.

    `usuario`/`ip` são opcionais e só servem para o evento de auditoria."""
    inicio = agora_ms()
    chave_bytes = _chave_bytes(chave)
    dados = _aplicar_padding(texto.encode('utf-8'))
    iv = os.urandom(TAMANHO_BLOCO)
    corpo = _cifrar_cbc(dados, _subchaves(chave_bytes), iv)
    resultado = base64.urlsafe_b64encode(iv + corpo + _tag(chave_bytes, iv, corpo)).decode('ascii')
    # Só metadados: nunca o texto, a chave nem o texto cifrado.
    registrar_evento(
        'cifragem', usuario=usuario, ip=ip, origem='mensageria_cripto',
        duracao_ms=round(agora_ms() - inicio, 3),
        detalhes={'bytes_entrada': len(texto.encode('utf-8')), 'blocos': len(corpo) // TAMANHO_BLOCO,
                  'rodadas': NUM_RODADAS, 'versao': VERSAO},
    )
    return resultado


def decifrar(texto_cifrado, chave, usuario='', ip=None):
    """Confere a autenticação ANTES de decifrar: chave errada ou texto
    adulterado falham sempre, sem decifrar nada. Levanta a exceção para quem
    chamou, mas antes registra a falha no log de segurança e na tabela de
    eventos (alimenta a detecção de "falhas de descriptografia")."""
    inicio = agora_ms()
    try:
        chave_bytes = _chave_bytes(chave)
        iv, corpo, tag = _decompor(texto_cifrado)
        if not hmac.compare_digest(tag, _tag(chave_bytes, iv, corpo)):
            raise ValueError('autenticação inválida (chave incorreta ou mensagem adulterada)')
        subchaves = _subchaves(chave_bytes)
        blocos, anterior = [], iv
        for i in range(0, len(corpo), TAMANHO_BLOCO):
            bloco = corpo[i:i + TAMANHO_BLOCO]
            blocos.append(_xor_bytes(_decifrar_bloco(bloco, subchaves), anterior))
            anterior = bloco
        resultado = _remover_padding(b''.join(blocos)).decode('utf-8')
    except Exception as exc:
        logger.warning('falha_decriptografia motivo=%s: %s', type(exc).__name__, exc)
        registrar_evento(
            'falha_decifragem', usuario=usuario, ip=ip, origem='mensageria_cripto',
            duracao_ms=round(agora_ms() - inicio, 3),
            detalhes={'motivo': type(exc).__name__},
        )
        raise
    registrar_evento(
        'decifragem', usuario=usuario, ip=ip, origem='mensageria_cripto',
        duracao_ms=round(agora_ms() - inicio, 3),
        detalhes={'blocos': len(blocos), 'versao': VERSAO},
    )
    return resultado


def migrar_da_v1(texto_cifrado_v1, chave_v1):
    """Decifra uma mensagem da v1 e a recifra na v2 com uma chave nova.
    Usado pela migration 0056. Retorna (texto_cifrado_v2, chave_v2)."""
    from . import cifra_v1_legada
    texto = cifra_v1_legada.decifrar(texto_cifrado_v1, chave_v1)
    chave = gerar_chave()
    return cifrar(texto, chave), chave


def migrar_para_v1(texto_cifrado_v2, chave_v2):
    """Inverso de migrar_da_v1 (só para desfazer a migration 0056)."""
    from . import cifra_v1_legada
    texto = decifrar(texto_cifrado_v2, chave_v2)
    chave = cifra_v1_legada.gerar_chave()
    return cifra_v1_legada.cifrar(texto, chave), chave
