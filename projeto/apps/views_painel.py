"""View do painel de segurança (dashboard de ataques e anomalias).

Acesso restrito à equipe (is_staff): o painel mostra IPs de origem,
resultados de ataques e alertas, ou seja, informação útil para quem quer
atacar o sistema. Anônimo vai para o login; usuário logado sem permissão
recebe 403, e a tentativa vira um evento `acesso_negado` (que a própria IA
analisa depois).
"""
import logging

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import render

from .eventos import ip_da_requisicao, registrar_evento
from .painel import PERIODOS, dados_painel

logger = logging.getLogger('security')


@login_required
def painel_seguranca(request):
    if not request.user.is_staff:
        logger.warning('Acesso negado: usuario=%s tentou abrir o painel de seguranca',
                       request.user.username)
        registrar_evento('acesso_negado', usuario=request.user.username, ip=ip_da_requisicao(request),
                         origem='painel_seguranca', detalhes={'motivo': 'nao_staff'})
        raise PermissionDenied

    try:
        dias = int(request.GET.get('dias', 14))
    except ValueError:
        dias = 14
    if dias not in PERIODOS:
        dias = 14
    incluir_simulados = request.GET.get('simulados', '1') != '0'

    dados = dados_painel(dias=dias, incluir_simulados=incluir_simulados)
    return render(request, 'painel_seguranca.html', {
        **dados,
        'dias': dias,
        'periodos': PERIODOS.items(),
    })
