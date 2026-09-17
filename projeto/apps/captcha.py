"""
Verificação server-side do Google reCAPTCHA v2, usada no login e cadastro
para dificultar força bruta e criação automatizada de contas.
"""
import logging

import requests
from django.conf import settings

logger = logging.getLogger('security')

RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'


def recaptcha_valido(request):
    token = request.POST.get('g-recaptcha-response', '')
    if not token:
        return False

    try:
        resposta = requests.post(
            RECAPTCHA_VERIFY_URL,
            data={
                'secret': settings.RECAPTCHA_SECRET_KEY,
                'response': token,
                'remoteip': request.META.get('REMOTE_ADDR'),
            },
            timeout=10,
        )
        resultado = resposta.json()
    except requests.RequestException as exc:
        logger.error('Falha ao verificar reCAPTCHA: %s', exc)
        return False

    return resultado.get('success', False)
