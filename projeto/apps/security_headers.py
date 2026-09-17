"""
Cabeçalhos de segurança que o Django não define nativamente
(Content-Security-Policy, Permissions-Policy). X-Content-Type-Options e
X-Frame-Options já vêm do SecurityMiddleware/XFrameOptionsMiddleware do
próprio Django; HSTS vem de SECURE_HSTS_SECONDS (settings.py), condicional a
TARGET_ENV=prod -- só é enviado sob HTTPS de verdade, nunca em dev local.

--------------------------------------------------------------------------
Content-Security-Policy (CSP)
--------------------------------------------------------------------------
Lista de permissão explícita para cada tipo de recurso que o navegador pode
carregar, construída a partir do que a aplicação realmente usa hoje
(levantado buscando por <script src=, <link rel=stylesheet> e @import em
todos os templates): jQuery e Bootstrap via jsDelivr/code.jquery.com,
Font Awesome via cdnjs, Google Fonts, e o widget do reCAPTCHA (script +
iframe) via google.com/gstatic.com.

Limitação conhecida e deliberada: `script-src`/`style-src` incluem
'unsafe-inline' porque a aplicação tem blocos <script>/<style> inline
espalhados por vários templates (não usa nonce nem arquivo externo para
esse JS/CSS específico dos templates). Isso reduz a proteção da CSP contra
XSS refletido/armazenado que injete <script> inline -- o ponto mais forte
de defesa contra XSS neste projeto continua sendo o autoescape padrão do
Django (nenhum `|safe`/`mark_safe` no projeto, ver JUSTIFICATIVAS_SEGURANCA.md).
Migrar os poucos scripts/estilos inline para nonce por requisição
removeria essa exceção; não foi feito nesta rodada por ser um refactor de
todos os templates, não uma correção de uma vulnerabilidade concreta.

--------------------------------------------------------------------------
Permissions-Policy
--------------------------------------------------------------------------
A aplicação não usa câmera, microfone, geolocalização nem nenhuma outra API
de hardware/sensor do navegador (confirmado buscando por <video>, <audio>,
geolocation e getUserMedia em todos os templates) -- por isso todas essas
permissões são desabilitadas para o próprio site e para qualquer conteúdo
embutido, sem risco de quebrar funcionalidade existente.
"""

CSP_DIRECTIVES = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'", "'unsafe-inline'",
        'https://cdn.jsdelivr.net', 'https://code.jquery.com',
        'https://www.google.com', 'https://www.gstatic.com',
    ],
    'style-src': [
        "'self'", "'unsafe-inline'",
        'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com',
    ],
    'font-src': [
        "'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com',
    ],
    'img-src': ["'self'", 'data:'],
    'connect-src': ["'self'"],
    'frame-src': ['https://www.google.com', 'https://www.gstatic.com'],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
}

CSP_HEADER_VALUE = '; '.join(
    f"{diretiva} {' '.join(fontes)}" for diretiva, fontes in CSP_DIRECTIVES.items()
)

# () -- lista vazia de origens permitidas = recurso bloqueado para todo mundo,
# inclusive o próprio site.
PERMISSIONS_POLICY_HEADER_VALUE = ', '.join([
    'camera=()', 'microphone=()', 'geolocation=()', 'payment=()',
    'usb=()', 'magnetometer=()', 'gyroscope=()', 'accelerometer=()',
    'autoplay=()',
])


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault('Content-Security-Policy', CSP_HEADER_VALUE)
        response.setdefault('Permissions-Policy', PERMISSIONS_POLICY_HEADER_VALUE)
        return response
