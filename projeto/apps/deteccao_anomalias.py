"""
IA de detecção de anomalias (etapa 5 da arquitetura: análise comportamental).

Entrada: a tabela EventoSeguranca (camada Big Data), resumida por
`analise_eventos.features_por_janela()` em uma linha por (entidade, janela
de 5 minutos), onde entidade = IP de origem (ou o usuário, quando não há IP).

Saída: um evento `anomalia` na própria tabela para cada janela suspeita,
com pontuação, motivo e as features que mais se desviaram. É o que o
dashboard lê.

COMO DECIDE (detector híbrido, o mesmo desenho de um SIEM: assinatura +
comportamento):

  1. Regras de assinatura: limiares fixos para ataques conhecidos (ex.: 10
     falhas de login em 5 min, qualquer arquivo adulterado). Alta precisão e
     fáceis de explicar, mas só pegam o que alguém previu e escreveu.
     Alerta CRÍTICO.
  2. Isolation Forest (scikit-learn), não supervisionado. Aprende o que é
     "normal" a partir dos próprios dados, sem rótulo e sem limiar escrito
     à mão, então também acusa combinações que nenhuma regra cobre. A ideia
     do algoritmo: um ponto raro é separado do resto com poucos cortes
     aleatórios; a pontuação vem da profundidade média em que o ponto é
     isolado nas árvores. Recebe só janelas com pelo menos MIN_EVENTOS
     eventos: a imensa maioria das janelas tem 1 evento só e, se entrassem,
     as rajadas de ataque se perdiam no meio delas (medido: F1 ~0,1).
     Alerta só do modelo = ALERTA (precisa de triagem), ou CRÍTICO se a
     pontuação passar de SCORE_CRITICO.

O rótulo `cenario_simulado` (gabarito dos dados sintéticos) NUNCA entra no
modelo. Só é usado em `avaliar()` para medir acerto e é repassado no
evento de anomalia para o dashboard mostrar se o alerta bateu com o gabarito.
"""
import ipaddress
import math
from datetime import datetime

from .analise_eventos import TIPOS_FEATURE, features_por_janela
from .eventos import registrar_evento
from .models import EventoSeguranca

JANELA_MINUTOS = 5
MIN_EVENTOS = 3            # janelas menores não vão para o modelo
# Fração esperada de janelas suspeitas entre as que vão ao modelo. Escolhida
# na calibração (seed 42) entre 0,02 / 0,03 / 0,04 e validada em outras sementes.
CONTAMINACAO = 0.03
MIN_JANELAS_MODELO = 50    # com menos que isso o Isolation Forest não é confiável -> só as regras
N_ARVORES = 300
SEMENTE = 42               # resultado reproduzível
SCORE_CRITICO = 0.70       # pontuação (0 a 1) a partir da qual o alerta é crítico
ORIGEM = 'deteccao_anomalias'

# Eventos que não descrevem comportamento de usuário/IP: os próprios alertas
# da IA e os resumos dos ataques simulados da Pessoa 2.
TIPOS_IGNORADOS = ('anomalia', 'ataque_forca_bruta', 'ataque_diferencial', 'ataque_estatistico')

COLUNAS = ['total', *TIPOS_FEATURE, 'usuarios_distintos', 'taxa_falha_login']

DESCRICAO = {
    'total': 'volume incomum de eventos',
    'login_sucesso': 'número incomum de logins',
    'login_falha': 'número incomum de falhas de login',
    'login_bloqueado': 'número incomum de logins barrados pelo CAPTCHA',
    'cifragem': 'volume incomum de cifragens',
    'decifragem': 'volume incomum de decifragens',
    'falha_decifragem': 'frequência elevada de falhas de decifragem',
    'acesso_negado': 'padrão atípico de acessos negados',
    'integridade_violada': 'arquivo alterado (SHA-256 não confere)',
    'moderacao_ia': 'volume incomum de avaliações moderadas',
    'usuarios_distintos': 'muitos usuários a partir da mesma origem',
    'taxa_falha_login': 'proporção alta de falhas de login',
}

# Regras de assinatura: feature -> (limiar por janela, motivo).
# 10 em 5 minutos segue a ordem de grandeza das políticas usuais de bloqueio
# de conta (OWASP sugere bloquear após poucas tentativas). Não foram
# ajustadas olhando o gabarito.
REGRAS = {
    'integridade_violada': (1, 'regra_integridade_violada'),
    'login_falha': (10, 'regra_forca_bruta_login'),
    'falha_decifragem': (10, 'regra_falhas_decifragem'),
    'acesso_negado': (10, 'regra_acessos_negados'),
    'total': (100, 'regra_volume_eventos'),
}


def _matriz(linhas):
    """Features numéricas. Contagens em log1p: uma rajada de 150 não pode
    dominar a escala inteira.

    A hora do dia ficou DE FORA de propósito. Testado na calibração (seed 42,
    primeira versão do detector, com só a regra de integridade):
    com ela, janelas normais de madrugada já parecem "raras" e disputam o
    orçamento de alertas com os ataques (F1 0,849 x 0,914 sem ela, com
    contaminação 0,03)."""
    import numpy as np

    return np.array([[math.log1p(l[c]) if c != 'taxa_falha_login' else l[c] for c in COLUNAS]
                     for l in linhas], dtype=float).reshape(len(linhas), len(COLUNAS))


def _importar_isolation_forest():
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # pragma: no cover - depende do ambiente
        raise ImportError(
            'scikit-learn não está instalado. Rode: pip install -r requirements-ia.txt') from exc
    return IsolationForest


def detectar(linhas, contaminacao=CONTAMINACAO, semente=SEMENTE):
    """Classifica cada janela. Devolve (resultados, info), com um resultado
    por linha de entrada, na mesma ordem:
      anomala, metodo ('regra' | 'isolation_forest' | 'regra+isolation_forest' | ''),
      score (0 a 1, ou None se a janela não foi ao modelo), pred_modelo, pred_regra,
      regras (motivos disparados), motivo, descricao e destaques (as features que
      mais pesaram: {feature: {valor, mediana}} do modelo ou {valor, limiar} da regra).

    numpy/scikit-learn só são importados quando há janelas para o modelo: a
    camada de regras funciona sem o requirements-ia.txt instalado.
    """
    n = len(linhas)
    resultados = [{'anomala': False, 'metodo': '', 'score': None, 'pred_modelo': False,
                   'pred_regra': False, 'regras': [], 'motivo': '', 'descricao': '',
                   'destaques': {}} for _ in range(n)]
    ativas = [i for i, l in enumerate(linhas) if l['total'] >= MIN_EVENTOS]
    info = {'janelas': n, 'janelas_ativas': len(ativas), 'modelo_usado': False,
            'contaminacao': contaminacao}

    if len(ativas) >= MIN_JANELAS_MODELO:
        import numpy as np

        IsolationForest = _importar_isolation_forest()
        X = _matriz([linhas[i] for i in ativas])
        modelo = IsolationForest(n_estimators=N_ARVORES, contamination=contaminacao,
                                 random_state=semente).fit(X)
        scores = -modelo.score_samples(X)          # 0..1; quanto maior, mais anômala
        preds = modelo.predict(X) == -1
        # Para explicar o alerta: quanto cada feature se afastou da média (z-score, em log).
        media, desvio = X.mean(axis=0), X.std(axis=0)
        brutos = np.array([[linhas[i][c] for c in COLUNAS] for i in ativas], dtype=float)
        medianas = np.median(brutos, axis=0)
        for k, i in enumerate(ativas):
            r = resultados[i]
            r['score'] = round(float(scores[k]), 4)
            r['pred_modelo'] = bool(preds[k])
            if preds[k]:
                z = np.where(desvio > 0, (X[k] - media) / np.where(desvio > 0, desvio, 1), 0)
                ordem = [j for j in np.argsort(-z) if z[j] > 0][:3]
                r['destaques'] = {COLUNAS[j]: {'valor': linhas[i][COLUNAS[j]],
                                               'mediana': float(medianas[j])} for j in ordem}
                principal = COLUNAS[ordem[0]] if ordem else 'total'
                r.update(anomala=True, metodo='isolation_forest',
                         motivo=f'atipico_{principal}', descricao=DESCRICAO[principal])
        info['modelo_usado'] = True

    for i, l in enumerate(linhas):
        disparadas = [(campo, motivo) for campo, (limiar, motivo) in REGRAS.items() if l[campo] >= limiar]
        if not disparadas:
            continue
        r = resultados[i]
        campo, motivo = disparadas[0]
        r.update(anomala=True, pred_regra=True, motivo=motivo, descricao=DESCRICAO[campo],
                 regras=[m for _, m in disparadas],
                 metodo='regra+isolation_forest' if r['pred_modelo'] else 'regra')
        r['destaques'] = {**{c: {'valor': l[c], 'limiar': REGRAS[c][0]} for c, _ in disparadas},
                          **{k: v for k, v in r['destaques'].items() if k not in dict(disparadas)}}
    return resultados, info


def _severidade(r):
    if r['metodo'].startswith('regra') or (r['score'] or 0) >= SCORE_CRITICO:
        return EventoSeguranca.CRITICO
    return EventoSeguranca.ALERTA


def _eh_ip(valor):
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def id_janela(linha, minutos=JANELA_MINUTOS):
    return f"{minutos}m|{linha['entidade']}|{linha['janela_inicio']}"


def persistir(linhas, resultados, minutos=JANELA_MINUTOS):
    """Grava um evento `anomalia` por janela suspeita. Idempotente: uma janela
    já registrada antes não é gravada de novo. Devolve (novas, repetidas)."""
    existentes = {
        (d or {}).get('id_janela')
        for d in EventoSeguranca.objects.filter(tipo=EventoSeguranca.ANOMALIA, origem=ORIGEM)
        .values_list('detalhes', flat=True)
    }
    novas = repetidas = 0
    for linha, r in zip(linhas, resultados):
        if not r['anomala']:
            continue
        chave_janela = id_janela(linha, minutos)
        if chave_janela in existentes:
            repetidas += 1
            continue
        entidade = linha['entidade']
        evento = registrar_evento(
            EventoSeguranca.ANOMALIA,
            usuario='' if _eh_ip(entidade) else entidade,
            ip=entidade if _eh_ip(entidade) else None,
            origem=ORIGEM,
            severidade=_severidade(r),
            sucesso=False,
            simulado=bool(linha.get('cenario_simulado')),
            criado_em=datetime.fromisoformat(linha['janela_inicio']),
            detalhes={
                'id_janela': chave_janela,
                'entidade': entidade,
                'janela_inicio': linha['janela_inicio'],
                'janela_minutos': minutos,
                'metodo': r['metodo'],
                'score': r['score'],
                'motivo': r['motivo'],
                'descricao': r['descricao'],
                'destaques': r['destaques'],
                'total_eventos': linha['total'],
                # Gabarito (só em dado simulado). Não foi usado para detectar.
                'cenario_simulado': linha.get('cenario_simulado') or None,
            },
        )
        if evento:
            novas += 1
            existentes.add(chave_janela)
    return novas, repetidas


def _metricas(y, pred):
    tp = sum(1 for a, b in zip(y, pred) if a and b)
    fp = sum(1 for a, b in zip(y, pred) if not a and b)
    fn = sum(1 for a, b in zip(y, pred) if a and not b)
    tn = len(y) - tp - fp - fn
    precisao = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precisao * recall / (precisao + recall) if precisao + recall else 0.0
    return {'vp': tp, 'fp': fp, 'fn': fn, 'vn': tn, 'alertas': tp + fp,
            'precisao': round(precisao, 4), 'recall': round(recall, 4), 'f1': round(f1, 4)}


def avaliar(linhas, resultados):
    """Compara as previsões com o gabarito dos dados simulados.

    Só considera janelas que têm gabarito (eventos do gerador sintético).
    Mede as duas camadas separadas (só regras, só Isolation Forest) e o
    detector híbrido, que é o usado de fato.
    """
    pares = [(l, r) for l, r in zip(linhas, resultados) if l.get('cenario_simulado')]
    if not pares:
        return None
    y = [l['cenario_simulado'] != 'normal' for l, _ in pares]
    so_regras = [r['pred_regra'] for _, r in pares]
    so_modelo = [r['pred_modelo'] for _, r in pares]
    hibrido = [r['anomala'] for _, r in pares]

    por_cenario = {}
    for l, r in pares:
        c = por_cenario.setdefault(l['cenario_simulado'], {'janelas': 0, 'hibrido': 0,
                                                           'isolation_forest': 0, 'regras': 0})
        c['janelas'] += 1
        c['hibrido'] += r['anomala']
        c['isolation_forest'] += r['pred_modelo']
        c['regras'] += r['pred_regra']
    return {
        'janelas_avaliadas': len(pares),
        'janelas_anomalas': sum(y),
        'regras': _metricas(y, so_regras),
        'isolation_forest': _metricas(y, so_modelo),
        'hibrido': _metricas(y, hibrido),
        # Janelas anômalas que SÓ o modelo pegou (nenhuma regra disparou).
        'so_o_modelo_detectou': sum(1 for a, r in zip(y, (r for _, r in pares))
                                    if a and r['pred_modelo'] and not r['pred_regra']),
        'por_cenario': dict(sorted(por_cenario.items())),
    }


def executar(minutos=JANELA_MINUTOS, incluir_simulados=True, gravar=True, com_avaliacao=False,
             contaminacao=CONTAMINACAO):
    """Ponto de entrada usado pelo comando `detectar_anomalias`."""
    linhas = features_por_janela(minutos, incluir_simulados, excluir_tipos=TIPOS_IGNORADOS)
    resultados, info = detectar(linhas, contaminacao=contaminacao)
    info['anomalias'] = sum(r['anomala'] for r in resultados)
    info['novas'], info['repetidas'] = persistir(linhas, resultados, minutos) if gravar else (0, 0)
    info['avaliacao'] = avaliar(linhas, resultados) if com_avaliacao else None
    info['alertas'] = [
        {**{k: linha[k] for k in ('entidade', 'janela_inicio', 'total', 'cenario_simulado')}, **r}
        for linha, r in zip(linhas, resultados) if r['anomala']
    ]
    return info
