"""
Importa o histórico de logs/security.log (anterior à tabela de eventos) para
EventoSeguranca, para não perder o que já foi registrado em arquivo.

É idempotente (cada linha tem um SHA-1; rodar de novo não duplica) e, por
padrão, só importa linhas ANTERIORES ao primeiro evento gravado direto pela
aplicação -- depois disso o app já grava na tabela e importar duplicaria.

    python manage.py importar_logs_seguranca [--arquivo logs/security.log] [--tudo]
"""
import hashlib
import re
from datetime import datetime

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.eventos import CATALOGO, TIPOS_DE_FALHA
from apps.masking import pseudonimizar
from apps.models import EventoSeguranca

LINHA = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ \[(\w+)\] (.*)$')
KV = re.compile(r'(\w+)=(\S+)')

# (prefixo da mensagem, tipo, origem)
REGRAS = [
    ('Login bem-sucedido', 'login_sucesso', 'login_view'),
    ('Login falhou', 'login_falha', 'login_view'),
    ('Login bloqueado', 'login_bloqueado', 'login_view'),
    ('Acesso negado', 'acesso_negado', 'views'),
    ('Integridade violada', 'integridade_violada', 'verificar_integridade_arquivos'),
    ('falha_decriptografia', 'falha_decifragem', 'mensageria_cripto'),
    ('moderacao_ia', 'moderacao_ia', 'ai_moderation'),
]


def _identificador(kv):
    """usuario do log; e-mails (PII) viram pseudônimo. 'cliente' já vem pseudonimizado."""
    if kv.get('usuario'):
        return kv['usuario']
    if kv.get('cliente'):
        return kv['cliente']
    return pseudonimizar(kv.get('email') or '') or ''


class Command(BaseCommand):
    help = 'Importa logs/security.log para a tabela EventoSeguranca (idempotente).'

    def add_arguments(self, parser):
        parser.add_argument('--arquivo', default=str(settings.LOG_DIR / 'security.log'))
        parser.add_argument('--tudo', action='store_true',
                            help='ignora o corte (importa linhas mesmo posteriores ao 1º evento direto)')

    def handle(self, *args, **opts):
        corte = None
        if not opts['tudo']:
            primeiro = (EventoSeguranca.objects.filter(simulado=False).exclude(origem__startswith='log:')
                        .order_by('criado_em').values_list('criado_em', flat=True).first())
            corte = primeiro

        existentes = {
            d.get('linha_sha1') for d in
            EventoSeguranca.objects.filter(origem__startswith='log:').values_list('detalhes', flat=True)
        }
        novos, ignorados, duplicados = [], 0, 0
        vistas = {}
        with open(opts['arquivo'], encoding='utf-8', errors='replace') as f:
            for linha in f:
                linha = linha.rstrip('\n')
                m = LINHA.match(linha)
                if not m:
                    continue
                ts, nivel, msg = m.groups()
                regra = next((r for r in REGRAS if msg.startswith(r[0])), None)
                if not regra:
                    ignorados += 1
                    continue
                quando = timezone.make_aware(datetime.strptime(ts, '%Y-%m-%d %H:%M:%S'))
                if corte and quando >= corte:
                    ignorados += 1
                    continue
                # Linhas idênticas no mesmo segundo são eventos distintos (ex.: 2
                # tentativas de login iguais): o hash inclui o nº da ocorrência.
                repeticao = vistas.get(linha, 0)
                vistas[linha] = repeticao + 1
                sha = hashlib.sha1(f'{linha}#{repeticao}'.encode('utf-8')).hexdigest()
                if sha in existentes:
                    duplicados += 1
                    continue
                existentes.add(sha)
                kv = dict(KV.findall(msg))
                tipo = regra[1]
                ip = kv.get('ip')
                categoria, sev = CATALOGO[tipo]
                detalhes = {'linha_sha1': sha, 'nivel_log': nivel}
                if kv.get('status'):
                    detalhes['status'] = kv['status']
                if kv.get('motivo'):
                    detalhes['motivo'] = kv['motivo'].rstrip(':')
                if 'senha incorreta' in msg:
                    detalhes['motivo'] = 'senha_incorreta'
                elif 'email nao cadastrado' in msg:
                    detalhes['motivo'] = 'email_nao_cadastrado'
                novos.append(EventoSeguranca(
                    criado_em=quando, tipo=tipo, categoria=categoria, severidade=sev,
                    sucesso=tipo not in TIPOS_DE_FALHA and kv.get('status') != 'rejeitado',
                    usuario=_identificador(kv)[:150],
                    ip=ip if ip and ip != 'None' else None,
                    origem=f'log:{regra[2]}'[:60], detalhes=detalhes,
                ))
        EventoSeguranca.objects.bulk_create(novos, batch_size=1000)
        self.stdout.write(self.style.SUCCESS(
            f'{len(novos)} eventos importados | {duplicados} já importados | {ignorados} linhas ignoradas '
            f'(sem regra{" ou após o corte" if corte else ""}).'))
