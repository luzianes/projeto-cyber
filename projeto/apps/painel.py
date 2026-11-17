"""
Dados do painel de segurança (etapa 6 da arquitetura: dashboard).

Lê só a tabela EventoSeguranca: os eventos de comportamento (camada Big
Data), os alertas `anomalia` gravados pela IA (deteccao_anomalias.py) e os
resumos dos ataques à cifra (ataques_cripto.py). Não importa scikit-learn,
então o painel funciona em qualquer ambiente, mesmo sem a IA instalada.

Tudo sai como dict/list simples. A view entrega isso ao template e o JS do
painel monta os gráficos.
"""
from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDay, TruncHour
from django.utils import timezone

from .models import EventoSeguranca

# Mesma lista da IA: eventos que não são comportamento de usuário/IP.
TIPOS_NAO_COMPORTAMENTO = ('anomalia', 'ataque_forca_bruta', 'ataque_diferencial', 'ataque_estatistico')
NOMES_TIPO = dict(EventoSeguranca.TIPOS)
PERIODOS = {1: 'Últimas 24 h', 7: 'Últimos 7 dias', 14: 'Últimos 14 dias', 30: 'Últimos 30 dias', 0: 'Tudo'}
NOMES_ATAQUE = {
    'ataque_diferencial': 'Diferencial (efeito avalanche)',
    'ataque_forca_bruta': 'Força bruta',
    'ataque_estatistico': 'Estatístico (análise de frequência)',
}
NOMES_METODO = {
    'regra': 'Regra',
    'isolation_forest': 'Isolation Forest',
    'regra+isolation_forest': 'Regra + Isolation Forest',
}


def _serie(qs, trunc):
    return {b: n for b, n in qs.annotate(b=trunc('criado_em')).values_list('b').annotate(n=Count('id')) if b}


def _escalares(detalhes):
    """Só os valores simples do resumo de um ataque (sem listas/dicts aninhados)."""
    return [(k, v) for k, v in (detalhes or {}).items()
            if k != 'parametros' and isinstance(v, (int, float, str, bool))]


def dados_painel(dias=14, incluir_simulados=True, limite_recentes=25):
    agora = timezone.now()
    qs = EventoSeguranca.objects.all()
    if not incluir_simulados:
        qs = qs.filter(simulado=False)
    if dias:
        qs = qs.filter(criado_em__gte=agora - timedelta(days=dias))

    comportamento = qs.exclude(tipo__in=TIPOS_NAO_COMPORTAMENTO)
    anomalias = qs.filter(tipo=EventoSeguranca.ANOMALIA)
    total = comportamento.count()
    falhas = comportamento.filter(sucesso=False).count()

    # Série temporal: por hora em períodos curtos, por dia nos longos.
    if dias and dias <= 2:
        trunc, rotulo = TruncHour, '%d/%m %Hh'
    else:
        trunc, rotulo = TruncDay, '%d/%m'
    serie_falhas = _serie(comportamento.filter(sucesso=False), trunc)
    serie_anomalias = _serie(anomalias, trunc)
    baldes = sorted(set(serie_falhas) | set(serie_anomalias))

    detalhes_anomalias = list(anomalias.values_list('detalhes', 'severidade'))
    por_motivo = Counter((d or {}).get('descricao') or 'sem descrição' for d, _ in detalhes_anomalias)
    por_metodo = Counter(NOMES_METODO.get((d or {}).get('metodo'), 'Outro') for d, _ in detalhes_anomalias)
    por_severidade = Counter(s for _, s in detalhes_anomalias)

    # Conferência com o gabarito: só faz sentido para alertas em dado simulado.
    com_gabarito = [(d or {}).get('cenario_simulado') for d, _ in detalhes_anomalias]
    com_gabarito = [c for c in com_gabarito if c]
    conferencia = None
    if com_gabarito:
        acertos = sum(1 for c in com_gabarito if c != 'normal')
        conferencia = {'alertas': len(com_gabarito), 'acertos': acertos,
                       'falsos_positivos': len(com_gabarito) - acertos,
                       'precisao': round(acertos / len(com_gabarito), 3)}

    top_origens = list(
        anomalias.exclude(ip__isnull=True).values_list('ip').annotate(n=Count('id')).order_by('-n')[:10])

    recentes = []
    for e in anomalias.order_by('-criado_em')[:limite_recentes]:
        d = e.detalhes or {}
        recentes.append({
            'quando': timezone.localtime(e.criado_em),
            'entidade': d.get('entidade') or e.ip or e.usuario or '-',
            'descricao': d.get('descricao', ''),
            'metodo': NOMES_METODO.get(d.get('metodo'), d.get('metodo', '')),
            'score': d.get('score'),
            'severidade': e.severidade,
            'total_eventos': d.get('total_eventos'),
            'destaques': [(k, v.get('valor'), v.get('mediana', v.get('limiar')), 'limiar' in v)
                          for k, v in (d.get('destaques') or {}).items()],
            'cenario_simulado': d.get('cenario_simulado'),
        })

    # Ataques: a execução mais recente de cada um (não filtra por período:
    # o veredito da cifra vale até alguém rodar os ataques de novo).
    ataques_qs = EventoSeguranca.objects.filter(categoria='ataque')
    ataques = []
    for tipo, nome in NOMES_ATAQUE.items():
        ultimo = ataques_qs.filter(tipo=tipo).order_by('-criado_em').first()
        ataques.append({
            'tipo': tipo, 'nome': nome,
            'execucoes': ataques_qs.filter(tipo=tipo).count(),
            'ultimo': ultimo and {
                'quando': timezone.localtime(ultimo.criado_em),
                'vulneravel': ultimo.sucesso,  # sucesso do ataque = vulnerabilidade encontrada
                'duracao_s': round((ultimo.duracao_ms or 0) / 1000, 2),
                'resumo': _escalares(ultimo.detalhes),
            },
        })

    por_tipo = list(comportamento.values_list('tipo').annotate(n=Count('id')).order_by('-n'))
    return {
        'periodo': PERIODOS.get(dias or 0, f'Últimos {dias} dias'),
        'incluir_simulados': incluir_simulados,
        'kpis': {
            'eventos': total,
            'falhas': falhas,
            'taxa_falha': round(100 * falhas / total, 1) if total else 0.0,
            'anomalias': len(detalhes_anomalias),
            'criticas': por_severidade.get(EventoSeguranca.CRITICO, 0),
            'alertas': por_severidade.get(EventoSeguranca.ALERTA, 0),
            'origens_suspeitas': anomalias.exclude(ip__isnull=True).values('ip').distinct().count(),
            'ataques_vulneraveis': sum(1 for a in ataques if a['ultimo'] and a['ultimo']['vulneravel']),
            'ataques_executados': sum(1 for a in ataques if a['ultimo']),
        },
        'conferencia': conferencia,
        'recentes': recentes,
        'ataques': ataques,
        'top_origens': top_origens,
        # Para os gráficos (vai ao template via json_script, nunca como HTML).
        'graficos': {
            'serie': {'rotulos': [timezone.localtime(b).strftime(rotulo) for b in baldes],
                      'falhas': [serie_falhas.get(b, 0) for b in baldes],
                      'anomalias': [serie_anomalias.get(b, 0) for b in baldes]},
            'por_motivo': por_motivo.most_common(),
            'por_metodo': por_metodo.most_common(),
            'por_tipo': [(NOMES_TIPO.get(t, t), n) for t, n in por_tipo],
        },
    }
