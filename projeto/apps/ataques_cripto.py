"""
Ataques à cifra própria da mensageria (Pessoa 2 — Ataques).

Alvo: apps/mensageria_cripto.py (Pessoa 1). Ataques pedidos no enunciado:

  1. Diferencial   -> ataque_diferencial()   responde "tem efeito avalanche?"
  2. Força bruta   -> ataque_forca_bruta()
  3. Estatístico   -> ataque_estatistico()

e veredito(...) responde "é seguro?". O comando `python manage.py rodar_ataques`
roda tudo, imprime o relatório e registra um evento-resumo por ataque na
tabela EventoSeguranca (Pessoa 4). A análise completa está em
docs/ATAQUES_CIFRA.md.

Princípio de Kerckhoffs: o atacante conhece o algoritmo inteiro (S-box, P-box,
número de rodadas, derivação das sub-chaves); o único segredo é a chave. Por
isso os ataques usam as tabelas internas do módulo da cifra, e sempre que
possível chamam as funções reais cifrar()/decifrar().

Os ataques rodam em "modo ataque" (ver modo_ataque): sem gravar eventos e sem
escrever falha_decriptografia no logs/security.log. A força bruta chama
decifrar() dezenas de milhares de vezes com chave errada; sem isso, cada
tentativa viraria uma linha no log, que o importar_logs_seguranca depois
transformaria em "falha de decifragem" falsa para a IA de anomalias.
"""
import base64
import functools
import itertools
import logging
import math
import os
import random
import statistics
import time
from collections import Counter
from contextlib import contextmanager

from . import mensageria_cripto as mc
from .eventos import agora_ms, registrar_evento, silenciar_eventos

BLOCO = mc.TAMANHO_BLOCO
CHAVE = mc.TAMANHO_CHAVE
RODADAS = mc.NUM_RODADAS
ANO_EM_S = 365.25 * 24 * 3600
BITS_MINIMOS_RECOMENDADOS = 128  # AES-128; o NIST não aceita menos de 112 bits de segurança


# --- infraestrutura --------------------------------------------------------

class _SemFalhaDeDecifragem(logging.Filter):
    def filter(self, record):
        return not str(record.msg).startswith('falha_decriptografia')


@contextmanager
def modo_ataque():
    """Durante o ataque: não grava eventos e não escreve as falhas de
    decifragem (esperadas, aos milhares) no log de segurança."""
    filtro = _SemFalhaDeDecifragem()
    mc.logger.addFilter(filtro)
    try:
        with silenciar_eventos():
            yield
    finally:
        mc.logger.removeFilter(filtro)


def _em_modo_ataque(funcao):
    @functools.wraps(funcao)
    def envolvida(*args, **kwargs):
        with modo_ataque():
            return funcao(*args, **kwargs)
    return envolvida


def _b64(dados):
    """bytes -> string base64, o formato de chave e de texto cifrado da cifra."""
    return base64.urlsafe_b64encode(dados).decode('ascii')


def _bytes_do_cifrado(texto_cifrado):
    return base64.urlsafe_b64decode(texto_cifrado.encode('ascii'))


def num(x, casas=0):
    """Número no formato brasileiro: 1.234.567,89."""
    return f'{x:,.{casas}f}'.replace(',', '_').replace('.', ',').replace('_', '.')


def _bits_diferentes(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def _bytes_diferentes(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


def cifrar_com_iv(texto_bytes, chave_bytes, iv):
    """Mesmo resultado de mc.cifrar() (em bytes, antes do base64), mas com o IV
    escolhido por quem chama. cifrar() sorteia um IV novo a cada chamada, o que
    deixa os dois resultados ~50% diferentes por causa do IV, não da cifra. No
    teste diferencial o IV precisa ficar fixo para medir só o efeito da mudança
    no texto. (test_ataques confere que isto bate byte a byte com cifrar().)"""
    subchaves = mc._subchaves(chave_bytes)
    dados = mc._aplicar_padding(texto_bytes)
    saida, anterior = [iv], iv
    for i in range(0, len(dados), BLOCO):
        anterior = mc._cifrar_bloco(mc._xor_bytes(dados[i:i + BLOCO], anterior), subchaves)
        saida.append(anterior)
    return b''.join(saida)


_SAUDACOES = ['Olá', 'Oi', 'Bom dia', 'Boa tarde', 'Boa noite', 'Olá, pessoal']
_PEDIDOS = [
    'quero reservar uma mesa para {n} pessoas no {dia}',
    'vocês têm opção sem lactose no cardápio?',
    'gostaria de saber se aceitam cartão de crédito',
    'o café especial de hoje ainda está disponível?',
    'posso levar meu cachorro para a área externa?',
    'qual o horário de funcionamento no {dia}?',
    'vou chegar às {h}h, podem guardar a mesa?',
    'adorei o atendimento de ontem, parabéns à equipe',
    'esqueci um guarda-chuva preto aí no {dia}',
    'vocês fazem encomenda de bolo para {n} pessoas?',
]
_DIAS = ['sábado', 'domingo', 'feriado', 'fim de semana', 'dia {d}']
_FECHOS = ['Obrigado!', 'Obrigada!', 'Aguardo retorno.', 'Até mais.', '']


def gerar_mensagens(qtd, rng):
    """Mensagens fictícias no estilo cliente -> cafeteria (corpus dos testes)."""
    mensagens = []
    for _ in range(qtd):
        dia = rng.choice(_DIAS).format(d=rng.randint(1, 28))
        pedido = rng.choice(_PEDIDOS).format(n=rng.randint(2, 12), dia=dia, h=rng.randint(8, 20))
        mensagens.append(f'{rng.choice(_SAUDACOES)}! {pedido[0].upper()}{pedido[1:]} '
                         f'{rng.choice(_FECHOS)}'.strip())
    return mensagens


def _parece_texto(texto):
    return bool(texto) and all(c.isprintable() or c in '\n\r\t' for c in texto)


# --- 1. Ataque diferencial (efeito avalanche) ------------------------------

def uniformidade_diferencial_sbox():
    """Maior entrada da tabela de distribuição de diferenças (DDT) da S-box:
    das 256 entradas x, quantas levam uma diferença de entrada fixa a uma mesma
    diferença de saída. Quanto menor, melhor (AES: 4; o pior possível: 256)."""
    sbox, pior = mc._SBOX, 0
    for dif_entrada in range(1, 256):
        contagem = Counter(sbox[x] ^ sbox[x ^ dif_entrada] for x in range(256))
        pior = max(pior, max(contagem.values()))
    return pior


@_em_modo_ataque
def ataque_diferencial(amostras=200, seed=42):
    """Altera 1 bit da entrada (texto ou chave), mantém o resto fixo e mede
    quanto a saída muda. Com efeito avalanche, ~50% dos bits mudariam."""
    rng = random.Random(seed)

    def sortear(n):
        return bytes(rng.randrange(256) for _ in range(n))

    # (a) 1 bit do texto, mesma chave e mesmo IV, 1 bloco
    bits_texto, max_bytes_texto = [], 0
    alcance = [set() for _ in range(BLOCO)]  # byte j da entrada -> bytes da saída que mudaram
    for _ in range(amostras):
        subchaves = mc._subchaves(sortear(CHAVE))
        entrada = sortear(BLOCO)
        base = mc._cifrar_bloco(entrada, subchaves)
        for bit in range(BLOCO * 8):
            alterada = bytearray(entrada)
            alterada[bit // 8] ^= 1 << (bit % 8)
            saida = mc._cifrar_bloco(bytes(alterada), subchaves)
            bits_texto.append(_bits_diferentes(base, saida))
            max_bytes_texto = max(max_bytes_texto, _bytes_diferentes(base, saida))
            alcance[bit // 8].update(i for i in range(BLOCO) if base[i] != saida[i])

    # (b) 1 bit da chave, mesmo texto, 1 bloco
    bits_chave, max_bytes_chave = [], 0
    for _ in range(amostras):
        chave, entrada = sortear(CHAVE), sortear(BLOCO)
        base = mc._cifrar_bloco(entrada, mc._subchaves(chave))
        for bit in range(CHAVE * 8):
            alterada = bytearray(chave)
            alterada[bit // 8] ^= 1 << (bit % 8)
            saida = mc._cifrar_bloco(entrada, mc._subchaves(bytes(alterada)))
            bits_chave.append(_bits_diferentes(base, saida))
            max_bytes_chave = max(max_bytes_chave, _bytes_diferentes(base, saida))

    # (c) mensagem inteira (com o encadeamento CBC): 1 bit no 1º bloco
    msg_pct, msg_bytes_por_bloco, antes_intactos = [], 0, True
    for _ in range(max(amostras // 4, 10)):
        chave, iv, texto = sortear(CHAVE), sortear(BLOCO), sortear(5 * BLOCO)
        base = cifrar_com_iv(texto, chave, iv)[BLOCO:]
        alterado = bytearray(texto)
        bit = rng.randrange(BLOCO * 8)
        alterado[bit // 8] ^= 1 << (bit % 8)
        saida = cifrar_com_iv(bytes(alterado), chave, iv)[BLOCO:]
        msg_pct.append(100 * _bits_diferentes(base, saida) / (len(base) * 8))
        for b in range(0, len(base), BLOCO):
            msg_bytes_por_bloco = max(msg_bytes_por_bloco,
                                      _bytes_diferentes(base[b:b + BLOCO], saida[b:b + BLOCO]))
        # e 1 bit no último bloco de texto: os blocos anteriores não mudam
        alterado = bytearray(texto)
        alterado[-1] ^= 1
        saida = cifrar_com_iv(bytes(alterado), chave, iv)[BLOCO:]
        antes_intactos &= base[:4 * BLOCO] == saida[:4 * BLOCO]

    # (d) o jeito "ingênuo": cifrar() real duas vezes (cada chamada sorteia um IV)
    ingenuo = []
    for texto in gerar_mensagens(max(amostras // 4, 10), rng):
        chave = mc.gerar_chave()
        pos = rng.randrange(len(texto))
        vizinho = texto[:pos] + chr(ord(texto[pos]) ^ 1) + texto[pos + 1:]
        c1, c2 = _bytes_do_cifrado(mc.cifrar(texto, chave)), _bytes_do_cifrado(mc.cifrar(vizinho, chave))
        if len(c1) == len(c2):
            ingenuo.append(100 * _bits_diferentes(c1, c2) / (len(c1) * 8))

    # (e) maleabilidade: o atacante altera o texto decifrado sem saber a chave
    original = 'Para 2 pessoas, sábado às 20h.'
    chave = mc.gerar_chave()
    cifrado = bytearray(_bytes_do_cifrado(mc.cifrar(original, chave)))
    cifrado[original.encode('utf-8').index(b'2')] ^= ord('2') ^ ord('9')  # só o IV (8 primeiros bytes)
    adulterado = mc.decifrar(_b64(bytes(cifrado)), chave)

    pct_texto = 100 * statistics.mean(bits_texto) / (BLOCO * 8)
    pct_chave = 100 * statistics.mean(bits_chave) / (BLOCO * 8)
    tem_avalanche = 45 <= pct_texto <= 55 and 45 <= pct_chave <= 55
    maleavel = adulterado == original.replace('2', '9', 1)
    mapa = [sorted(a) for a in alcance]
    delta = uniformidade_diferencial_sbox()
    return {
        'texto': {'bits_alterados_media': round(statistics.mean(bits_texto), 2),
                  'percentual_bits': round(pct_texto, 2), 'bytes_alterados_max': max_bytes_texto,
                  'mapa_entrada_saida': mapa,
                  'bytes_que_nao_mudam_de_posicao': [j for j, m in enumerate(mapa) if m == [j]]},
        'chave': {'bits_alterados_media': round(statistics.mean(bits_chave), 2),
                  'percentual_bits': round(pct_chave, 2), 'bytes_alterados_max': max_bytes_chave},
        'mensagem_cbc': {'percentual_bits': round(statistics.mean(msg_pct), 2),
                         'bytes_alterados_max_por_bloco': msg_bytes_por_bloco,
                         'blocos_anteriores_intactos': antes_intactos},
        'ingenuo_iv_aleatorio': {'percentual_bits': round(statistics.mean(ingenuo), 2)},
        'sbox': {'uniformidade_diferencial': delta, 'probabilidade': round(delta / 256, 4),
                 'referencia_aes': 4},
        'maleabilidade': {'original': original, 'adulterado': adulterado, 'maleavel': maleavel},
        'tem_avalanche': tem_avalanche,
        'vulnerabilidade_encontrada': not tem_avalanche or maleavel,
        'resumo': {
            'amostras': amostras, 'percentual_bits_texto': round(pct_texto, 2),
            'percentual_bits_chave': round(pct_chave, 2), 'ideal_percentual': 50.0,
            'bytes_alterados_max_por_bloco': max_bytes_texto,
            'percentual_ingenuo_iv_aleatorio': round(statistics.mean(ingenuo), 2),
            'sbox_uniformidade_diferencial': delta,
            'tem_avalanche': tem_avalanche, 'maleavel': maleavel,
        },
    }


# --- 2. Força bruta ---------------------------------------------------------

def _medir_taxa(texto_cifrado, tentativas=3000):
    """Chaves por segundo chamando o decifrar() real com chaves aleatórias."""
    inicio = time.perf_counter()
    for _ in range(tentativas):
        try:
            mc.decifrar(texto_cifrado, _b64(os.urandom(CHAVE)))
        except ValueError:
            pass
    return tentativas / (time.perf_counter() - inicio)


@_em_modo_ataque
def busca_exaustiva(texto_cifrado, prefixo_conhecido, bytes_desconhecidos):
    """Força bruta clássica: testa todas as 256^n chaves que completam o
    prefixo. Só com o texto cifrado: a chave certa é a que decifra com padding
    válido e gera texto legível."""
    for tentativa, valor in enumerate(range(256 ** bytes_desconhecidos), start=1):
        chave = prefixo_conhecido + valor.to_bytes(bytes_desconhecidos, 'big')
        try:
            texto = mc.decifrar(texto_cifrado, _b64(chave))
        except ValueError:  # padding inválido, UTF-8 inválido, base64 inválido
            continue
        if _parece_texto(texto):
            return chave, texto, tentativa
    return None, None, 256 ** bytes_desconhecidos


def trilhas():
    """A cifra não mistura bytes entre si: XOR e S-box agem byte a byte e a
    P-box só troca bytes de lugar. Logo, cada byte do bloco cifrado depende de
    UM byte da entrada e de 1 byte da chave por rodada. Para cada posição i do
    bloco cifrado devolve (posição de entrada, [índice do byte da chave em
    cada rodada]).

    Os índices saem rodando _subchaves() numa chave "marcadora" (0, 1, ..., 7):
    funciona porque a derivação só reordena bytes da chave."""
    marcadores = mc._subchaves(bytes(range(CHAVE)))
    resultado = []
    for i in range(BLOCO):
        posicoes, p = [0] * RODADAS, i
        for r in reversed(range(RODADAS)):
            p = mc._PBOX[p]  # _permutar: saida[i] = entrada[PBOX[i]]
            posicoes[r] = p
        resultado.append((posicoes[0], [marcadores[r][posicoes[r]] for r in range(RODADAS)]))
    return resultado


def _candidatos_da_trilha(pares):
    """pares: [(x, y)] com y = S(...S(S(x ^ k0) ^ k1)... ^ kR-1).
    Encontro no meio: chuta k0..kR-3 pela frente (256^(R-2) chutes = 2^16 com 4
    rodadas), chuta kR-1 por trás (256 chutes) e kR-2 sai por XOR. Devolve
    todas as tuplas (k0, ..., kR-1) coerentes com todos os pares."""
    sbox, inversa = mc._SBOX, mc._SBOX_INV
    tabela = {}
    for chute in itertools.product(range(256), repeat=RODADAS - 2):
        meio = []
        for x, _ in pares:
            for k in chute:
                x = sbox[x ^ k]
            meio.append(x)
        tabela.setdefault(tuple(m ^ meio[0] for m in meio), []).append((chute, meio[0]))
    candidatos = []
    for k_ultima in range(256):
        tras = [inversa[inversa[y] ^ k_ultima] for _, y in pares]  # = meio ^ kR-2
        for chute, meio0 in tabela.get(tuple(t ^ tras[0] for t in tras), ()):
            candidatos.append(chute + (meio0 ^ tras[0], k_ultima))
    return candidatos


@_em_modo_ataque
def recuperar_chave(texto_cifrado, prefixo_texto):
    """Ataque de texto conhecido "dividir para conquistar": em vez de 2^64
    chaves, ataca cada uma das 8 trilhas de byte separadamente (~2^16 chutes
    cada) e junta as respostas, que compartilham bytes da chave.
    prefixo_texto: início da mensagem que o atacante conhece (ex.: saudação
    padrão). Precisa de pelo menos 2 blocos inteiros (16 bytes); com 3 blocos
    a resposta é praticamente única."""
    bruto = _bytes_do_cifrado(texto_cifrado)
    conhecidos = len(prefixo_texto) // BLOCO
    if conhecidos < 2:
        raise ValueError('preciso de pelo menos 2 blocos (16 bytes) de texto conhecido')

    # No CBC, a entrada do bloco k é texto_k XOR cifrado_(k-1) (o IV para k=0),
    # e o atacante conhece os dois.
    entradas, saidas = [], []
    for k in range(conhecidos):
        anterior = bruto[k * BLOCO:(k + 1) * BLOCO]
        entradas.append(mc._xor_bytes(prefixo_texto[k * BLOCO:(k + 1) * BLOCO], anterior))
        saidas.append(bruto[(k + 1) * BLOCO:(k + 2) * BLOCO])

    restricoes = []
    for i, (pos_entrada, indices) in enumerate(trilhas()):
        pares = list(dict.fromkeys((e[pos_entrada], s[i]) for e, s in zip(entradas, saidas)))
        coerentes = []
        for candidato in _candidatos_da_trilha(pares):
            atribuicao = {}
            # a mesma posição da chave pode aparecer 2x na trilha: tem que bater
            if all(atribuicao.setdefault(j, v) == v for j, v in zip(indices, candidato)):
                coerentes.append(atribuicao)
        restricoes.append(coerentes)

    solucoes = [{}]
    for lista in sorted(restricoes, key=len):
        solucoes = [{**s, **a} for s in solucoes for a in lista
                    if all(s.get(j, v) == v for j, v in a.items())]
    chaves = [bytes(s[j] for j in range(CHAVE)) for s in solucoes if len(s) == CHAVE]

    for chave in chaves:  # confirma com o decifrar() real
        try:
            texto = mc.decifrar(texto_cifrado, _b64(chave))
        except ValueError:
            continue
        if texto.encode('utf-8').startswith(prefixo_texto[:conhecidos * BLOCO]) and _parece_texto(texto):
            return chave, texto, [len(r) for r in restricoes], len(chaves)
    return None, None, [len(r) for r in restricoes], len(chaves)


@_em_modo_ataque
def ataque_forca_bruta(bytes_desconhecidos=2, blocos_conhecidos=3, seed=42):
    rng = random.Random(seed)

    # (a) força bruta de verdade com chave reduzida artificialmente (2^(8n))
    mensagem = gerar_mensagens(1, rng)[0]
    chave_reduzida = bytes(CHAVE - bytes_desconhecidos) + bytes(
        rng.randrange(256) for _ in range(bytes_desconhecidos))
    cifrado = mc.cifrar(mensagem, _b64(chave_reduzida))
    inicio = time.perf_counter()
    achada, texto, tentativas = busca_exaustiva(
        cifrado, bytes(CHAVE - bytes_desconhecidos), bytes_desconhecidos)
    tempo_busca = time.perf_counter() - inicio

    # (b) extrapolação para a chave real de 64 bits
    taxa = _medir_taxa(cifrado)
    espaco = 256 ** CHAVE
    anos_pior = espaco / taxa / ANO_EM_S

    # (c) chave completa, dividir para conquistar com texto conhecido parcial
    prefixo = 'Olá, equipe da cafeteria! Tudo bem? '
    segredo = 'Meu voucher é CAFE-7Q2X-91 e a reserva está no nome de Ana Lima.'
    prefixo_bytes = prefixo.encode('utf-8')[:blocos_conhecidos * BLOCO]
    chave_real = mc.gerar_chave()  # chave dinâmica de verdade, 64 bits
    cifrado_real = mc.cifrar(prefixo + segredo, chave_real)
    inicio = time.perf_counter()
    recuperada, texto_recuperado, candidatos, solucoes = recuperar_chave(cifrado_real, prefixo_bytes)
    tempo_dc = time.perf_counter() - inicio
    quebrou_dc = recuperada is not None and _b64(recuperada) == chave_real

    return {
        'estimativa': {'espaco_chaves_bits': 8 * CHAVE, 'espaco_chaves': espaco,
                       'taxa_chaves_por_s': round(taxa), 'anos_pior_caso': anos_pior,
                       'anos_caso_medio': anos_pior / 2,
                       'minimo_recomendado_bits': BITS_MINIMOS_RECOMENDADOS},
        'reduzida': {'bits_desconhecidos': 8 * bytes_desconhecidos, 'espaco': 256 ** bytes_desconhecidos,
                     'tentativas': tentativas, 'tempo_s': round(tempo_busca, 3),
                     'quebrou': achada == chave_reduzida, 'texto_recuperado': texto},
        'dividir_conquistar': {'bytes_texto_conhecido': len(prefixo_bytes),
                               'candidatos_por_posicao': candidatos, 'chaves_coerentes': solucoes,
                               'tempo_s': round(tempo_dc, 3), 'quebrou': quebrou_dc,
                               'texto_recuperado': texto_recuperado},
        'vulnerabilidade_encontrada': quebrou_dc or 8 * CHAVE < BITS_MINIMOS_RECOMENDADOS,
        'resumo': {
            'espaco_chaves_bits': 8 * CHAVE, 'taxa_chaves_por_s': round(taxa),
            'anos_estimados_caso_medio': round(anos_pior / 2),
            'reduzida_bits': 8 * bytes_desconhecidos, 'reduzida_tentativas': tentativas,
            'reduzida_quebrou': achada == chave_reduzida,
            'dividir_conquistar_quebrou': quebrou_dc,
            'bytes_texto_conhecido': len(prefixo_bytes),
            'dividir_conquistar_s': round(tempo_dc, 3),
        },
    }


# --- 3. Ataque estatístico --------------------------------------------------

def _entropia(contagem, total):
    return -sum(n / total * math.log2(n / total) for n in contagem.values())


def _qui_quadrado_uniforme(contagem, total):
    esperado = total / 256
    return sum((contagem.get(b, 0) - esperado) ** 2 / esperado for b in range(256))


def _p_valor_qui2(x, gl=255):
    """Aproximação de Wilson-Hilferty (boa para gl grande), sem scipy."""
    z = ((x / gl) ** (1 / 3) - (1 - 2 / (9 * gl))) / math.sqrt(2 / (9 * gl))
    return 0.5 * math.erfc(z / math.sqrt(2))


def _perfil(dados):
    contagem = Counter(dados)
    total = len(dados)
    qui2 = _qui_quadrado_uniforme(contagem, total)
    mais_comuns = [(chr(b) if 32 <= b < 127 else f'0x{b:02x}', round(100 * n / total, 2))
                   for b, n in contagem.most_common(5)]
    return {'bytes': total, 'valores_distintos': len(contagem),
            'entropia_bits_por_byte': round(_entropia(contagem, total), 4),
            'qui_quadrado': round(qui2, 1), 'p_valor': _p_valor_qui2(qui2),
            'mais_comuns_pct': mais_comuns}


@_em_modo_ataque
def ataque_estatistico(qtd_mensagens=2000, seed=42):
    """Análise de frequência sobre um corpus cifrado com chave nova por
    mensagem (como no sistema). Se a distribuição dos bytes cifrados não for
    uniforme, dá para inferir o texto pela frequência (como numa cifra de
    substituição)."""
    rng = random.Random(seed)
    mensagens = gerar_mensagens(qtd_mensagens, rng)
    claro, cifrado, tamanhos = bytearray(), bytearray(), []
    for texto in mensagens:
        bruto = _bytes_do_cifrado(mc.cifrar(texto, mc.gerar_chave()))
        claro += texto.encode('utf-8')
        cifrado += bruto[BLOCO:]  # sem o IV: ele é aleatório por construção e "ajudaria" a cifra
        tamanhos.append((len(texto.encode('utf-8')), len(bruto) - BLOCO))
    perfil_claro, perfil_cifrado = _perfil(bytes(claro)), _perfil(bytes(cifrado))
    uniforme = perfil_cifrado['p_valor'] > 0.01

    # Blocos repetidos: 8 blocos idênticos de texto, com e sem o encadeamento
    repetido = b'mesa 07 ' * 8
    chave = os.urandom(CHAVE)
    com_cbc = _bytes_do_cifrado(mc.cifrar(repetido.decode(), _b64(chave)))[BLOCO:BLOCO * 9]
    subchaves = mc._subchaves(chave)
    sem_cbc = b''.join(mc._cifrar_bloco(repetido[i:i + BLOCO], subchaves)
                       for i in range(0, len(repetido), BLOCO))

    def distintos(dados):
        return len({dados[i:i + BLOCO] for i in range(0, len(dados), BLOCO)})

    # Mesma mensagem, mesma chave, cifrada duas vezes
    texto, chave_s = mensagens[0], mc.gerar_chave()
    a, b = _bytes_do_cifrado(mc.cifrar(texto, chave_s)), _bytes_do_cifrado(mc.cifrar(texto, chave_s))
    iguais_pct = 100 * (len(a) - _bytes_diferentes(a, b)) / len(a)

    # Vazamento de tamanho: len(cifrado) = 8 * (len(texto) // 8 + 1), então quem
    # vê só o cifrado sabe que len(texto) está entre len(cifrado) - 8 e len(cifrado) - 1.
    correlacao = statistics.correlation([t for t, _ in tamanhos], [c for _, c in tamanhos])
    na_faixa = sum(1 for t, c in tamanhos if c - BLOCO <= t <= c - 1)

    blocos_cbc, blocos_ecb = distintos(com_cbc), distintos(sem_cbc)
    return {
        'texto_claro': perfil_claro,
        'texto_cifrado': perfil_cifrado,
        'uniforme': uniforme,
        'blocos_repetidos': {'blocos_iguais_no_texto': 8, 'distintos_com_cbc': blocos_cbc,
                             'distintos_sem_cbc': blocos_ecb},
        'mesma_mensagem_duas_vezes_pct_bytes_iguais': round(iguais_pct, 2),
        'tamanho': {'correlacao_tamanho_claro_cifrado': round(correlacao, 4),
                    'mensagens_com_tamanho_deduzido': na_faixa, 'incerteza_bytes': BLOCO},
        'vulnerabilidade_encontrada': not uniforme or blocos_cbc < 8,
        'resumo': {
            'mensagens': qtd_mensagens, 'bytes_analisados': perfil_cifrado['bytes'],
            'entropia_claro': perfil_claro['entropia_bits_por_byte'],
            'entropia_cifrado': perfil_cifrado['entropia_bits_por_byte'],
            'qui2_cifrado': perfil_cifrado['qui_quadrado'],
            'p_valor_cifrado': round(perfil_cifrado['p_valor'], 4), 'uniforme': uniforme,
            'blocos_distintos_com_cbc': blocos_cbc, 'blocos_distintos_sem_cbc': blocos_ecb,
            'vaza_tamanho': na_faixa == len(tamanhos),
        },
    }


# --- veredito e execução ----------------------------------------------------

def veredito(diferencial, forca_bruta, estatistico):
    """Responde às duas perguntas do enunciado a partir dos números medidos."""
    dc = forca_bruta['dividir_conquistar']
    est = forca_bruta['estimativa']
    motivos = [
        f"Sem efeito avalanche: inverter 1 bit do texto muda em média "
        f"{num(diferencial['texto']['percentual_bits'], 1)}% dos bits do bloco (ideal: ~50%) e nunca mais "
        f"de {diferencial['texto']['bytes_alterados_max']} byte(s) por bloco; inverter 1 bit da chave muda "
        f"{num(diferencial['chave']['percentual_bits'], 1)}%.",
        f"Chave de {est['espaco_chaves_bits']} bits recuperada em {num(dc['tempo_s'], 1)} s com "
        f"{dc['bytes_texto_conhecido']} bytes de texto conhecido (cada byte é atacado separadamente)."
        if dc['quebrou'] else 'O ataque dividir-para-conquistar não recuperou a chave nesta execução.',
        f"Mesmo sem esse atalho, {est['espaco_chaves_bits']} bits está abaixo do mínimo recomendado "
        f"({est['minimo_recomendado_bits']} bits).",
    ]
    if diferencial['maleabilidade']['maleavel']:
        motivos.append(
            f"Maleável (não há autenticação): alterando 1 byte do IV, o texto decifrado virou "
            f"'{diferencial['maleabilidade']['adulterado']}' sem conhecer a chave.")
    if estatistico['uniforme']:
        motivos.append(
            f"Ponto positivo: a análise de frequência não funciona; os bytes cifrados são uniformes "
            f"(entropia {num(estatistico['texto_cifrado']['entropia_bits_por_byte'], 3)} bits/byte, "
            f"p = {num(estatistico['texto_cifrado']['p_valor'], 3)}), graças ao CBC com IV aleatório "
            f"e à chave nova por mensagem.")
    seguro = (diferencial['tem_avalanche'] and not diferencial['maleabilidade']['maleavel']
              and not dc['quebrou'] and estatistico['uniforme']
              and est['espaco_chaves_bits'] >= BITS_MINIMOS_RECOMENDADOS)
    return {'tem_avalanche': diferencial['tem_avalanche'], 'seguro': seguro, 'motivos': motivos}


ATAQUES = {
    'diferencial': ataque_diferencial,
    'forca_bruta': ataque_forca_bruta,
    'estatistico': ataque_estatistico,
}


def executar(nome, registrar=True, usuario='', **parametros):
    """Roda um ataque e registra UM evento-resumo (ataque_<nome>) na tabela
    EventoSeguranca. sucesso=True quando o ataque achou vulnerabilidade.
    Só metadados vão para o evento: nada de chave nem de texto."""
    inicio = agora_ms()
    resultado = ATAQUES[nome](**parametros)
    resultado['duracao_ms'] = round(agora_ms() - inicio, 3)
    resultado['evento_id'] = None
    if registrar:
        evento = registrar_evento(
            f'ataque_{nome}', usuario=usuario, origem='ataques_cripto',
            duracao_ms=resultado['duracao_ms'],
            sucesso=resultado['vulnerabilidade_encontrada'],
            detalhes={**resultado['resumo'], 'parametros': parametros},
        )
        resultado['evento_id'] = evento.pk if evento else None
    return resultado
