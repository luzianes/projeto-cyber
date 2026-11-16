"""
Processamento e análise dos eventos (camada Big Data).

Este módulo é a "API de dados" consumida pela IA de anomalias e pelo dashboard:

  * IA de anomalias: `features_por_janela()` devolve uma linha por
    (entidade, janela de tempo) já com contagens prontas para virar matriz de
    features (Isolation Forest, z-score etc.). `exportar_csv()` grava em CSV.
  * Dashboard: `resumo_geral()`, `serie_temporal()` e `top_origens()`
    devolvem estruturas simples (dict/list) prontas para gráficos.

Tudo roda no banco (agregações) ou em streaming (`.iterator()`), então escala
para centenas de milhares de eventos sem carregar a tabela inteira na memória.
"""
import csv
from collections import defaultdict
from datetime import timedelta

from django.db.models import Avg, Count, Max, Q
from django.db.models.functions import TruncDay, TruncHour

from .models import EventoSeguranca

# Tipos que viram colunas de contagem nas features da IA.
TIPOS_FEATURE = [
    'login_sucesso', 'login_falha', 'login_bloqueado', 'cifragem', 'decifragem',
    'falha_decifragem', 'acesso_negado', 'integridade_violada', 'moderacao_ia',
]


def eventos(incluir_simulados=True):
    qs = EventoSeguranca.objects.all()
    return qs if incluir_simulados else qs.filter(simulado=False)


def resumo_geral(incluir_simulados=True):
    qs = eventos(incluir_simulados)
    total = qs.count()
    falhas = qs.filter(sucesso=False).count()
    return {
        'total': total,
        'falhas': falhas,
        'taxa_falha': round(falhas / total, 4) if total else 0.0,
        'por_tipo': dict(qs.values_list('tipo').annotate(n=Count('id')).order_by('-n')),
        'por_categoria': dict(qs.values_list('categoria').annotate(n=Count('id')).order_by('-n')),
        'por_severidade': dict(qs.values_list('severidade').annotate(n=Count('id')).order_by('-n')),
        'ips_distintos': qs.exclude(ip__isnull=True).values('ip').distinct().count(),
        'usuarios_distintos': qs.exclude(usuario='').values('usuario').distinct().count(),
        'primeiro_evento': qs.order_by('criado_em').values_list('criado_em', flat=True).first(),
        'ultimo_evento': qs.aggregate(m=Max('criado_em'))['m'],
        'duracao_media_ms_por_tipo': {
            r['tipo']: round(r['m'], 3)
            for r in qs.exclude(duracao_ms__isnull=True).values('tipo').annotate(m=Avg('duracao_ms'))
        },
    }


def serie_temporal(tipo=None, granularidade='hora', incluir_simulados=True):
    """[(datetime_do_balde, quantidade), ...] ordenado. granularidade: 'hora'|'dia'."""
    trunc = TruncHour if granularidade == 'hora' else TruncDay
    qs = eventos(incluir_simulados)
    if tipo:
        qs = qs.filter(tipo=tipo)
    return list(
        qs.annotate(balde=trunc('criado_em')).values_list('balde').annotate(n=Count('id')).order_by('balde')
    )


def top_origens(tipo, campo='ip', limite=10, incluir_simulados=True):
    """Quem mais gerou eventos de um tipo. campo: 'ip' ou 'usuario'."""
    qs = eventos(incluir_simulados).filter(tipo=tipo)
    qs = qs.exclude(ip__isnull=True) if campo == 'ip' else qs.exclude(usuario='')
    return list(qs.values_list(campo).annotate(n=Count('id')).order_by('-n')[:limite])


def features_por_janela(minutos=5, incluir_simulados=True):
    """Agrega eventos por (entidade, janela) para a IA de anomalias.

    Entidade = IP (ou, sem IP, o usuário). Cada linha:
      entidade, janela_inicio, total, <contagem por tipo>, usuarios_distintos,
      taxa_falha_login, hora_do_dia, cenario_simulado (rótulo, só p/ avaliação).

    `cenario_simulado` vem do gerador de eventos sintéticos ('normal' ou o
    nome da anomalia injetada) e existe para medir a IA; NÃO deve ser usado
    como feature de treino.
    """
    janela = timedelta(minutes=minutos).total_seconds()
    acumulado = defaultdict(lambda: {
        'total': 0, 'usuarios': set(), 'cenarios': set(), **{t: 0 for t in TIPOS_FEATURE},
    })
    qs = eventos(incluir_simulados).values_list('criado_em', 'tipo', 'ip', 'usuario', 'detalhes')
    for criado_em, tipo, ip, usuario, detalhes in qs.iterator(chunk_size=5000):
        entidade = ip or usuario or 'desconhecida'
        inicio = int(criado_em.timestamp() // janela * janela)
        linha = acumulado[(entidade, inicio)]
        linha['total'] += 1
        if tipo in linha:
            linha[tipo] += 1
        if usuario:
            linha['usuarios'].add(usuario)
        cenario = (detalhes or {}).get('cenario')
        if cenario:
            linha['cenarios'].add(cenario)

    from datetime import datetime, timezone as _tz
    resultado = []
    for (entidade, inicio), linha in sorted(acumulado.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        tentativas = linha['login_sucesso'] + linha['login_falha'] + linha['login_bloqueado']
        anomalos = linha['cenarios'] - {'normal'}
        dt = datetime.fromtimestamp(inicio, tz=_tz.utc)
        resultado.append({
            'entidade': entidade,
            'janela_inicio': dt.isoformat(),
            'total': linha['total'],
            **{t: linha[t] for t in TIPOS_FEATURE},
            'usuarios_distintos': len(linha['usuarios']),
            'taxa_falha_login': round((linha['login_falha'] + linha['login_bloqueado']) / tentativas, 4) if tentativas else 0.0,
            'hora_do_dia': dt.hour,
            'cenario_simulado': (sorted(anomalos)[0] if anomalos else ('normal' if linha['cenarios'] else '')),
        })
    return resultado


def exportar_csv(caminho, linhas, colunas=None):
    """Grava uma lista de dicts em CSV (UTF-8 com BOM, abre certo no Excel)."""
    linhas = list(linhas)
    colunas = colunas or (list(linhas[0].keys()) if linhas else [])
    with open(caminho, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=colunas, extrasaction='ignore')
        w.writeheader()
        w.writerows(linhas)
    return len(linhas)


def eventos_para_dicts(incluir_simulados=True):
    """Eventos crus (sem segredos) como dicts, em streaming, para exportação."""
    qs = eventos(incluir_simulados).order_by('criado_em')
    for e in qs.iterator(chunk_size=5000):
        yield {
            'id': e.id, 'criado_em': e.criado_em.isoformat(), 'tipo': e.tipo,
            'categoria': e.categoria, 'severidade': e.severidade, 'sucesso': int(e.sucesso),
            'usuario': e.usuario, 'ip': e.ip or '', 'origem': e.origem,
            'duracao_ms': '' if e.duracao_ms is None else e.duracao_ms,
            'simulado': int(e.simulado), 'detalhes': e.detalhes,
        }
