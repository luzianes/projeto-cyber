from django.apps import AppConfig


class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps'

    def ready(self):
        # Esconde a versao do Python/SO (ex: "CPython/3.12.3") no header
        # "Server" das respostas do runserver -- information disclosure
        # desnecessario mesmo em dev. Sem efeito em producao, que deve usar
        # gunicorn/uwsgi (nunca o runserver do Django) atras de um proxy.
        # O header vem de ServerHandler.server_software (wsgiref), nao do
        # version_string() do http.server usado por requisicoes nao-WSGI.
        from django.core.servers.basehttp import ServerHandler, WSGIRequestHandler
        ServerHandler.server_software = 'WSGIServer'
        WSGIRequestHandler.version_string = lambda self: 'WSGIServer'
