"""
Cifra v1 da mensageria (versão original da Pessoa 1), mantida SOMENTE para:

  * a migration 0056, que decifra as mensagens antigas e as recifra com a v2;
  * o comando `rodar_ataques --cifra v1`, que reproduz os ataques do "antes".

NÃO usar para cifrar dados novos: os ataques mostraram que a v1 não tem efeito
avalanche, tem chave de 64 bits recuperável em ~1 s com texto conhecido e é
maleável (ver docs/ATAQUES_CIFRA.md). A cifra em uso é a de
mensageria_cripto.py. Não remover este módulo enquanto a migration 0056 existir.

Algoritmo idêntico ao original: blocos de 8 bytes, chave de 8 bytes, 4 rodadas
de XOR com sub-chave (rotação da chave) + S-box + P-box, CBC com IV aleatório,
PKCS7, saída em base64 (IV + blocos). Sem registro de eventos.
"""
import base64
import os
import random

VERSAO = 'v1'
TAMANHO_BLOCO = 8
TAMANHO_CHAVE = 8
NUM_RODADAS = 4
TAMANHO_TAG = 0  # sem autenticação


def _gerar_sbox():
    valores = list(range(256))
    random.Random(42).shuffle(valores)
    return valores


_SBOX = _gerar_sbox()
_SBOX_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _SBOX_INV[_v] = _i

_PBOX = [3, 0, 4, 1, 7, 2, 6, 5]
_PBOX_INV = [0] * TAMANHO_BLOCO
for _i, _v in enumerate(_PBOX):
    _PBOX_INV[_v] = _i


def gerar_chave():
    return base64.urlsafe_b64encode(os.urandom(TAMANHO_CHAVE)).decode('utf-8')


def _subchaves(chave_bytes):
    return [chave_bytes[r % len(chave_bytes):] + chave_bytes[:r % len(chave_bytes)]
            for r in range(NUM_RODADAS)]


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _substituir(bloco, tabela):
    return bytes(tabela[byte] for byte in bloco)


def _permutar(bloco, tabela):
    return bytes(bloco[tabela[i]] for i in range(len(bloco)))


def _cifrar_bloco(bloco, subchaves):
    estado = bloco
    for sub in subchaves:
        estado = _permutar(_substituir(_xor_bytes(estado, sub), _SBOX), _PBOX)
    return estado


def _decifrar_bloco(bloco, subchaves):
    estado = bloco
    for sub in reversed(subchaves):
        estado = _xor_bytes(_substituir(_permutar(estado, _PBOX_INV), _SBOX_INV), sub)
    return estado


def _aplicar_padding(dados):
    faltam = TAMANHO_BLOCO - (len(dados) % TAMANHO_BLOCO)
    return dados + bytes([faltam] * faltam)


def _remover_padding(dados):
    if not dados:
        raise ValueError('padding inválido: dados vazios')
    faltam = dados[-1]
    if faltam < 1 or faltam > TAMANHO_BLOCO or faltam > len(dados) \
            or dados[-faltam:] != bytes([faltam]) * faltam:
        raise ValueError('padding inválido (provável chave incorreta)')
    return dados[:-faltam]


def _cifrar_cbc(dados, subchaves, iv):
    """dados já com padding -> blocos cifrados (sem o IV)."""
    saida, anterior = [], iv
    for i in range(0, len(dados), TAMANHO_BLOCO):
        anterior = _cifrar_bloco(_xor_bytes(dados[i:i + TAMANHO_BLOCO], anterior), subchaves)
        saida.append(anterior)
    return b''.join(saida)


def _decompor(texto_cifrado):
    """string base64 -> (iv, blocos cifrados, tag). A v1 não tem tag."""
    bruto = base64.urlsafe_b64decode(texto_cifrado.encode('utf-8'))
    return bruto[:TAMANHO_BLOCO], bruto[TAMANHO_BLOCO:], b''


def cifrar(texto, chave, usuario='', ip=None):
    subchaves = _subchaves(base64.urlsafe_b64decode(chave.encode('utf-8')))
    iv = os.urandom(TAMANHO_BLOCO)
    corpo = _cifrar_cbc(_aplicar_padding(texto.encode('utf-8')), subchaves, iv)
    return base64.urlsafe_b64encode(iv + corpo).decode('utf-8')


def decifrar(texto_cifrado, chave, usuario='', ip=None):
    subchaves = _subchaves(base64.urlsafe_b64decode(chave.encode('utf-8')))
    iv, corpo, _ = _decompor(texto_cifrado)
    blocos, anterior = [], iv
    for i in range(0, len(corpo), TAMANHO_BLOCO):
        bloco = corpo[i:i + TAMANHO_BLOCO]
        blocos.append(_xor_bytes(_decifrar_bloco(bloco, subchaves), anterior))
        anterior = bloco
    return _remover_padding(b''.join(blocos)).decode('utf-8')
