"""
Cifra simétrica própria do Projeto 2, usada na mensageria privada
cliente -> cafeteria.

DESENHO (rede de substituição-permutação, remontando o que faz a AES, mas de forma simplificada):

  texto (utf-8) -> blocos de 8 bytes (com padding PKCS7)
      -> encadeamento entre blocos (estilo CBC, com IV aleatório)
          -> para cada bloco, N rodadas de:
                 XOR com a sub-chave da rodada (confusão com a chave)
                 substituição byte-a-byte via S-box fixa    (confusão)
                 permutação da ordem dos bytes no bloco     (difusão)
      -> IV + blocos cifrados, tudo em base64 (string, pra caber no banco)

Peças do requisito (Parte 2, slide 7):
  - "Chave não pode ser fixa": gerar_chave() sorteia bytes novos a cada
    chamada -- cada mensagem usa uma chave diferente.
  - "XOR / Substituição / Permutação / Blocos": presentes explicitamente
    nas rodadas acima.
  - "Difusão/Confusão": confusão vem do XOR+S-box (não-linear); difusão
    vem da permutação dentro do bloco e do encadeamento entre blocos
    (um bit alterado no início deveria afetar todos os blocos seguintes).

O S-box e o P-box são FIXOS e públicos (não são segredo -- no AES de
verdade também são públicos; quem protege os dados é só a chave). Isso é
proposital: facilita implementar decifrar() como o inverso exato de
cifrar(), que é onde a maioria dos bugs desse tipo de exercício acontece.

PARA QUEM FOR MEXER (Pessoa 2 - ataques):
  - Força bruta: a chave tem 8 bytes (2^64 possibilidades) -- buscar
    exaustivamente por todas é inviável de rodar de verdade. Duas opções
    pro trabalho: (a) CALCULAR o espaço de chaves e o tempo estimado pra
    testar tudo (o PDF aceita "testar OU calcular"), ou (b) demonstrar o
    MÉTODO de força bruta usando uma chave artificialmente menor (ex:
    truncar pra 2 bytes só na hora do teste) pra conseguir rodar de fato
    em tempo razoável.
  - Diferencial: mude 1 byte do texto de entrada (mesma chave) e compare
    os dois resultados de cifrar() -- compare byte a byte / bit a bit.
  - Estatístico: rode cifrar() em textos variados e olhe a distribuição
    de frequência dos bytes do resultado (antes do base64).
"""
import base64
import os
import random

TAMANHO_BLOCO = 8  # bytes
TAMANHO_CHAVE = 8  # bytes -- ver nota de força bruta acima
NUM_RODADAS = 4


# --- S-box fixa (substituição) ---------------------------------------
# Permutação fixa e pública dos 256 valores possíveis de 1 byte. Gerada
# uma única vez com uma semente fixa 
def _gerar_sbox():
    valores = list(range(256))
    random.Random(42).shuffle(valores)
    return valores

_SBOX = _gerar_sbox()
_SBOX_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _SBOX_INV[_v] = _i


# --- P-box fixa (permutação da ordem dos bytes dentro do bloco) ------
_PBOX = [3, 0, 4, 1, 7, 2, 6, 5]  # permutação fixa de 8 posições
_PBOX_INV = [0] * TAMANHO_BLOCO
for _i, _v in enumerate(_PBOX):
    _PBOX_INV[_v] = _i


def gerar_chave():
    """Chave dinâmica: bytes aleatórios novos a cada chamada (requisito:
    'não pode ser fixa'). Retorna como string base64 (pra caber no
    campo CharField do model)."""
    return base64.urlsafe_b64encode(os.urandom(TAMANHO_CHAVE)).decode('utf-8')


def _subchaves(chave_bytes):
    """Deriva uma sub-chave diferente para cada rodada, a partir da
    chave principal (rotaciona os bytes -- não é criptograficamente
    sofisticado, só precisa variar a cada rodada)."""
    subchaves = []
    for rodada in range(NUM_RODADAS):
        deslocamento = rodada % len(chave_bytes)
        sub = chave_bytes[deslocamento:] + chave_bytes[:deslocamento]
        subchaves.append(sub)
    return subchaves


def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _substituir(bloco, tabela):
    return bytes(tabela[byte] for byte in bloco)


def _permutar(bloco, tabela):
    return bytes(bloco[tabela[i]] for i in range(len(bloco)))


def _permutar_inverso(bloco, tabela_inv):
    # Mesmo formato de _permutar(), só que com a tabela invertida --
    # "ler da posição tabela_inv[i]" desfaz exatamente "ler da posição
    # tabela[i]" feito na cifragem. (Um `saida[tabela_inv[i]] = valor`
    # parece o jeito "óbvio" de inverter, mas inverte errado -- é a
    # direção oposta do que o índice realmente representa.)
    return bytes(bloco[tabela_inv[i]] for i in range(len(bloco)))


def _cifrar_bloco(bloco, subchaves):
    estado = bloco
    for sub in subchaves:
        estado = _xor_bytes(estado, sub)
        estado = _substituir(estado, _SBOX)
        estado = _permutar(estado, _PBOX)
    return estado


def _decifrar_bloco(bloco, subchaves):
    estado = bloco
    for sub in reversed(subchaves):
        estado = _permutar_inverso(estado, _PBOX_INV)
        estado = _substituir(estado, _SBOX_INV)
        estado = _xor_bytes(estado, sub)
    return estado


def _aplicar_padding(dados):
    """PKCS7: completa o último bloco, sempre adiciona pelo menos 1 byte
    (mesmo se já for múltiplo do tamanho do bloco) para o padding ser
    removível sem ambiguidade."""
    faltam = TAMANHO_BLOCO - (len(dados) % TAMANHO_BLOCO)
    return dados + bytes([faltam] * faltam)


def _remover_padding(dados):
    faltam = dados[-1]
    return dados[:-faltam]


def cifrar(texto, chave):
    """texto: str. chave: string base64 (de gerar_chave()).
    Retorna: string base64 contendo IV + blocos cifrados."""
    chave_bytes = base64.urlsafe_b64decode(chave.encode('utf-8'))
    subchaves = _subchaves(chave_bytes)

    dados = _aplicar_padding(texto.encode('utf-8'))
    iv = os.urandom(TAMANHO_BLOCO)

    blocos_cifrados = [iv]
    anterior = iv
    for i in range(0, len(dados), TAMANHO_BLOCO):
        bloco = dados[i:i + TAMANHO_BLOCO]
        # Encadeamento estilo CBC: XOR com o bloco cifrado anterior antes
        # de cifrar -- garante que alterar um byte no começo do texto
        # mude todos os blocos cifrados a partir dali (difusão na
        # mensagem inteira, não só dentro de 1 bloco).
        bloco_encadeado = _xor_bytes(bloco, anterior)
        cifrado = _cifrar_bloco(bloco_encadeado, subchaves)
        blocos_cifrados.append(cifrado)
        anterior = cifrado

    return base64.urlsafe_b64encode(b''.join(blocos_cifrados)).decode('utf-8')


def decifrar(texto_cifrado, chave):
    chave_bytes = base64.urlsafe_b64decode(chave.encode('utf-8'))
    subchaves = _subchaves(chave_bytes)

    bruto = base64.urlsafe_b64decode(texto_cifrado.encode('utf-8'))
    iv, corpo = bruto[:TAMANHO_BLOCO], bruto[TAMANHO_BLOCO:]

    blocos_decifrados = []
    anterior = iv
    for i in range(0, len(corpo), TAMANHO_BLOCO):
        bloco_cifrado = corpo[i:i + TAMANHO_BLOCO]
        decifrado = _decifrar_bloco(bloco_cifrado, subchaves)
        original = _xor_bytes(decifrado, anterior)
        blocos_decifrados.append(original)
        anterior = bloco_cifrado

    dados = _remover_padding(b''.join(blocos_decifrados))
    return dados.decode('utf-8')
