"""
Camada de registro de eventos (Big Data) do SecureAI Lab.

Uso, de qualquer ponto do código:

    from .eventos import registrar_evento
    registrar_evento('login_falha', usuario='ana', ip='10.0.0.5', origem='login_view')

Garantias:
  * NUNCA levanta exceção: falha ao gravar evento não pode derrubar login,
    cifragem etc. (o erro vai para o log de segurança em arquivo).
  * Usa um savepoint, então um erro de banco aqui não "envenena" a transação
    atômica de quem chamou.
  * Não grava segredos: quem chama deve passar só metadados em `detalhes`.
    Como defesa em profundidade, chaves sensíveis conhecidas são removidas.
"""
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from time import perf_counter

from django.db import transaction

logger = logging.getLogger('security')

# tipo -> (categoria, severidade padrão)
CATALOGO = {
    'cifragem': ('criptografia', 'info'),
    'decifragem': ('criptografia', 'info'),
    'falha_decifragem': ('criptografia', 'alerta'),
    'login_sucesso': ('autenticacao', 'info'),
    'login_falha': ('autenticacao', 'alerta'),
    'login_bloqueado': ('autenticacao', 'alerta'),
    'acesso_negado': ('autorizacao', 'alerta'),
    'integridade_violada': ('integridade', 'critico'),
    'moderacao_ia': ('ia', 'info'),
    'esteganografia': ('esteganografia', 'info'),
    'ataque_forca_bruta': ('ataque', 'info'),
    'ataque_diferencial': ('ataque', 'info'),
    'ataque_estatistico': ('ataque', 'info'),
    'anomalia': ('anomalia', 'critico'),
}

# Eventos que representam algo "ruim" -> sucesso=False por padrão.
TIPOS_DE_FALHA = {
    'falha_decifragem', 'login_falha', 'login_bloqueado',
    'acesso_negado', 'integridade_violada',
}

_silenciado = ContextVar('eventos_silenciado', default=False)

_CAMPOS_PROIBIDOS = {
    'chave', 'key', 'senha', 'password', 'token', 'texto', 'texto_claro',
    'texto_cifrado', 'plaintext', 'secret',
}


def _limpar_detalhes(detalhes):
    return {k: v for k, v in (detalhes or {}).items() if str(k).lower() not in _CAMPOS_PROIBIDOS}


def registrar_evento(tipo, *, usuario='', ip=None, origem='', duracao_ms=None,
                     sucesso=None, severidade=None, detalhes=None, simulado=False,
                     criado_em=None):
    """Grava um evento na tabela EventoSeguranca. Retorna o objeto ou None.

    `criado_em` é opcional (padrão: agora). Serve para eventos derivados que
    descrevem um momento passado, ex.: a anomalia detectada numa janela de
    ontem fica datada na própria janela, não na hora em que a IA rodou."""
    if _silenciado.get():
        return None
    try:
        from .models import EventoSeguranca

        categoria, sev_padrao = CATALOGO.get(tipo, ('anomalia', 'info'))
        if sucesso is None:
            sucesso = tipo not in TIPOS_DE_FALHA
        extra = {'criado_em': criado_em} if criado_em is not None else {}
        with transaction.atomic():
            return EventoSeguranca.objects.create(
                **extra,
                tipo=tipo,
                categoria=categoria,
                severidade=severidade or sev_padrao,
                sucesso=sucesso,
                usuario=(usuario or '')[:150],
                ip=ip or None,
                origem=(origem or '')[:60],
                duracao_ms=duracao_ms,
                detalhes=_limpar_detalhes(detalhes),
                simulado=simulado,
            )
    except Exception as exc:  # nunca derrubar o fluxo principal
        logger.error('Falha ao registrar evento tipo=%s: %s: %s', tipo, type(exc).__name__, exc)
        return None


def ip_da_requisicao(request):
    """IP de origem. Usa REMOTE_ADDR de propósito (mesma escolha do login_view):
    X-Forwarded-For é forjável pelo cliente, então só vale atrás de proxy confiável."""
    return request.META.get('REMOTE_ADDR') if request is not None else None


def agora_ms():
    """Relógio monotônico em ms, para medir duração: fim - inicio."""
    return perf_counter() * 1000


@contextmanager
def silenciar_eventos():
    """Suspende o registro de eventos dentro do bloco.

    Para os scripts de ataque: força bruta chama decifrar() milhares
    de vezes com chave errada; sem isto cada tentativa viraria uma linha no
    banco (e uma "falha de decifragem" falsa, poluindo a IA de anomalias).
    O padrão é rodar o ataque silenciado e registrar UM evento-resumo com
    registrar_evento('ataque_forca_bruta', ...) no final.
    """
    token = _silenciado.set(True)
    try:
        yield
    finally:
        _silenciado.reset(token)
