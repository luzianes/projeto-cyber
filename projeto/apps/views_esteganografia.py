"""Endpoints autenticados; arquivos e segredos não são salvos na sessão/banco."""
import base64
import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.http import require_GET, require_POST

from . import esteganografia_servico as servico
from .esteganografia import ErroEsteganografia, MAX_PIXELS, MAX_UPLOAD_BYTES
from .eventos import agora_ms, ip_da_requisicao, registrar_evento


@never_cache
@login_required
@require_GET
def esteganografia(request):
    return render(request, 'esteganografia.html', {
        'max_upload_mb': MAX_UPLOAD_BYTES // (1024 * 1024),
        'max_pixels': MAX_PIXELS, 'max_mensagem_bytes': servico.MAX_MENSAGEM_BYTES,
    })


@sensitive_variables()
def _operar(request, ocultar):
    inicio = agora_ms()
    try:
        kwargs = {'usuario': request.user.username, 'ip': ip_da_requisicao(request)}
        arquivo = request.FILES.get('imagem')
        chave = request.POST.get('chave', '')
        if ocultar:
            mensagem = request.POST.get('mensagem', '')
            # Multipart normaliza quebras de linha; o formulário web envia a
            # string JSON para preservar exatamente LF, CRLF, NUL e espaços.
            if 'mensagem_json' in request.POST:
                try:
                    mensagem = json.loads(request.POST['mensagem_json'])
                    if not isinstance(mensagem, str):
                        raise ValueError
                except (ValueError, RecursionError):
                    registrar_evento(
                        'esteganografia', **kwargs, origem='views_esteganografia',
                        sucesso=False, severidade='alerta',
                        duracao_ms=round(agora_ms() - inicio, 3), detalhes={
                            'operacao': 'ocultacao', 'resultado': 'falha',
                            'motivo': 'mensagem_invalida',
                        },
                    )
                    raise ErroEsteganografia('mensagem_invalida', 'O formato da mensagem é inválido.') from None
            resultado = servico.ocultar_mensagem(
                arquivo, mensagem, chave, **kwargs,
            )
            resultado['imagem_base64'] = base64.b64encode(resultado.pop('imagem_png')).decode('ascii')
        else:
            resultado = servico.extrair_mensagem(arquivo, chave, **kwargs)
        return JsonResponse({'sucesso': True, **resultado})
    except ErroEsteganografia as exc:
        return JsonResponse({'sucesso': False, 'erro': str(exc), 'codigo': exc.codigo}, status=400)
    except Exception:
        # A auditoria do serviço já registra a falha sem conteúdo de exceções.
        return JsonResponse({
            'sucesso': False, 'codigo': 'erro_interno',
            'erro': 'Não foi possível processar a imagem. Tente novamente com uma imagem válida.',
        }, status=500)


@never_cache
@sensitive_post_parameters('mensagem', 'mensagem_json', 'chave')
@login_required
@require_POST
def ocultar(request):
    return _operar(request, ocultar=True)


@never_cache
@sensitive_post_parameters('mensagem', 'mensagem_json', 'chave')
@login_required
@require_POST
def extrair(request):
    return _operar(request, ocultar=False)
