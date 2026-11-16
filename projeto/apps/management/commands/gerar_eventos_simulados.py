"""
Gera um grande volume de eventos SINTÉTICOS (tráfego normal + anomalias
injetadas) para treinar/avaliar a IA de anomalias e alimentar o dashboard.

Os eventos têm simulado=True e `detalhes.cenario` ('normal' ou o nome da
anomalia), que funciona como gabarito para medir acerto da IA.

    python manage.py gerar_eventos_simulados --qtd 50000 --dias 14
    python manage.py gerar_eventos_simulados --limpar      # apaga só os simulados
"""
import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.eventos import CATALOGO, TIPOS_DE_FALHA
from apps.models import EventoSeguranca

LOTE = 5000
USUARIOS = [f'cliente{i:02d}' for i in range(1, 41)] + ['empresario01', 'empresario02', 'empresario03']
# Horário comercial pesa mais (índice = hora do dia).
PESO_HORA = [1, 1, 1, 1, 1, 2, 3, 5, 8, 10, 10, 10, 9, 9, 10, 10, 10, 9, 8, 7, 5, 4, 2, 1]


class Command(BaseCommand):
    help = 'Gera eventos sintéticos (normais + anomalias) na tabela EventoSeguranca.'

    def add_arguments(self, parser):
        parser.add_argument('--qtd', type=int, default=20000, help='eventos de tráfego normal')
        parser.add_argument('--dias', type=int, default=14, help='janela de tempo (dias até agora)')
        parser.add_argument('--anomalias', type=int, default=25, help='nº de incidentes anômalos a injetar')
        parser.add_argument('--seed', type=int, default=42, help='semente (resultado reproduzível)')
        parser.add_argument('--limpar', action='store_true', help='só apaga os eventos simulados e sai')

    def handle(self, *args, **opts):
        if opts['limpar']:
            n, _ = EventoSeguranca.objects.filter(simulado=True).delete()
            self.stdout.write(self.style.SUCCESS(f'{n} eventos simulados apagados.'))
            return

        rng = random.Random(opts['seed'])
        agora = timezone.now()
        inicio = agora - timedelta(days=opts['dias'])
        # IP fixo por usuário (comportamento habitual) + alguns IPs "de fora".
        ip_de = {u: f'10.0.{rng.randint(0, 20)}.{rng.randint(2, 250)}' for u in USUARIOS}
        buffer, total = [], 0

        def ev(tipo, quando, usuario, ip, cenario, duracao=None, detalhes=None, severidade=None):
            categoria, sev = CATALOGO[tipo]
            return EventoSeguranca(
                criado_em=quando, tipo=tipo, categoria=categoria, severidade=severidade or sev,
                sucesso=tipo not in TIPOS_DE_FALHA, usuario=usuario, ip=ip,
                origem='gerador_simulado', duracao_ms=duracao, simulado=True,
                detalhes={'cenario': cenario, **(detalhes or {})},
            )

        def instante_normal():
            while True:
                t = inicio + timedelta(seconds=rng.uniform(0, (agora - inicio).total_seconds()))
                if rng.random() < PESO_HORA[t.hour] / 10:
                    return t

        def flush(forcar=False):
            nonlocal buffer, total
            if buffer and (forcar or len(buffer) >= LOTE):
                EventoSeguranca.objects.bulk_create(buffer, batch_size=LOTE)
                total += len(buffer)
                buffer = []

        # --- tráfego normal ---------------------------------------------
        for _ in range(opts['qtd']):
            u = rng.choice(USUARIOS)
            ip, t = ip_de[u], instante_normal()
            r = rng.random()
            if r < 0.30:
                buffer.append(ev('login_sucesso', t, u, ip, 'normal'))
            elif r < 0.34:
                buffer.append(ev('login_falha', t, u, ip, 'normal', detalhes={'motivo': 'senha_incorreta'}))
            elif r < 0.64:
                buffer.append(ev('cifragem', t, u, ip, 'normal', rng.gauss(0.6, 0.15),
                                 {'bytes_entrada': rng.randint(10, 400)}))
            elif r < 0.94:
                buffer.append(ev('decifragem', t, u, ip, 'normal', rng.gauss(0.5, 0.12)))
            elif r < 0.97:
                buffer.append(ev('moderacao_ia', t, u, ip, 'normal', detalhes={'status': 'aprovado'}))
            elif r < 0.99:
                buffer.append(ev('acesso_negado', t, u, ip, 'normal', detalhes={'motivo': 'nao_empresario'}))
            else:
                buffer.append(ev('falha_decifragem', t, u, ip, 'normal', detalhes={'motivo': 'ValueError'}))
            flush()

        # --- anomalias injetadas (cada uma é uma rajada concentrada) ------
        cenarios = ['forca_bruta_login', 'rajada_falha_decifragem', 'varredura_acesso_negado',
                    'geracao_incomum_de_eventos', 'integridade_violada']
        for i in range(opts['anomalias']):
            cenario = cenarios[i % len(cenarios)]
            t0 = instante_normal() if cenario != 'geracao_incomum_de_eventos' else \
                inicio + timedelta(days=rng.randint(0, max(opts['dias'] - 1, 1)), hours=3)
            atacante = f'203.0.113.{rng.randint(1, 254)}'  # faixa de documentação (TEST-NET-3)

            if cenario == 'forca_bruta_login':
                for k in range(rng.randint(40, 200)):
                    buffer.append(ev('login_falha', t0 + timedelta(seconds=k * rng.uniform(0.3, 2)),
                                     rng.choice(USUARIOS), atacante, cenario,
                                     detalhes={'motivo': 'senha_incorreta'}, severidade='critico'))
            elif cenario == 'rajada_falha_decifragem':
                u = rng.choice(USUARIOS)
                for k in range(rng.randint(30, 120)):
                    buffer.append(ev('falha_decifragem', t0 + timedelta(seconds=k * rng.uniform(0.2, 1.5)),
                                     u, ip_de[u], cenario, rng.gauss(0.4, 0.1),
                                     {'motivo': 'ValueError'}, 'critico'))
            elif cenario == 'varredura_acesso_negado':
                u = rng.choice(USUARIOS)
                for k in range(rng.randint(25, 90)):
                    buffer.append(ev('acesso_negado', t0 + timedelta(seconds=k * rng.uniform(0.5, 3)),
                                     u, atacante, cenario,
                                     detalhes={'motivo': 'idor_reserva', 'reserva_id': k + 1}, severidade='critico'))
            elif cenario == 'geracao_incomum_de_eventos':
                u = rng.choice(USUARIOS)
                for k in range(rng.randint(150, 400)):
                    buffer.append(ev('cifragem', t0 + timedelta(seconds=k * rng.uniform(0.05, 0.4)),
                                     u, ip_de[u], cenario, rng.gauss(0.6, 0.15),
                                     {'bytes_entrada': rng.randint(10, 400)}, 'alerta'))
            else:  # integridade_violada
                for k in range(rng.randint(2, 6)):
                    buffer.append(ev('integridade_violada', t0 + timedelta(seconds=k * 5), '', None, cenario,
                                     detalhes={'modelo': 'Cafe', 'campo': 'foto_ambiente'}))
            flush()

        flush(forcar=True)
        self.stdout.write(self.style.SUCCESS(
            f'{total} eventos simulados criados ({opts["qtd"]} normais + anomalias). '
            f'Use --limpar para removê-los.'))
