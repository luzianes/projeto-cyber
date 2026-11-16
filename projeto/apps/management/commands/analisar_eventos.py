"""
Relatório de análise dos eventos + exportação para a IA de anomalias e o
dashboard.

    python manage.py analisar_eventos
    python manage.py analisar_eventos --sem-simulados
    python manage.py analisar_eventos --csv eventos.csv --features-csv features.csv --janela 5
"""
from django.core.management.base import BaseCommand

from apps import analise_eventos as ae


class Command(BaseCommand):
    help = 'Resumo estatístico dos eventos de segurança e exportação CSV.'

    def add_arguments(self, parser):
        parser.add_argument('--sem-simulados', action='store_true', help='ignora eventos sintéticos')
        parser.add_argument('--csv', help='exporta os eventos crus para este CSV')
        parser.add_argument('--features-csv', help='exporta features por janela (entrada da IA) para este CSV')
        parser.add_argument('--janela', type=int, default=5, help='tamanho da janela, em minutos')

    def handle(self, *args, **o):
        inc = not o['sem_simulados']
        r = ae.resumo_geral(inc)
        w = self.stdout.write
        w(self.style.MIGRATE_HEADING('== Resumo dos eventos =='))
        w(f"Total: {r['total']} | falhas: {r['falhas']} ({r['taxa_falha']:.1%}) | "
          f"IPs: {r['ips_distintos']} | usuários: {r['usuarios_distintos']}")
        w(f"Período: {r['primeiro_evento']} -> {r['ultimo_evento']}")
        for titulo, chave in (('Por tipo', 'por_tipo'), ('Por categoria', 'por_categoria'),
                              ('Por severidade', 'por_severidade')):
            w(f'\n{titulo}:')
            for k, n in r[chave].items():
                w(f'  {k:<24} {n}')
        if r['duracao_media_ms_por_tipo']:
            w('\nDuração média (ms):')
            for k, v in r['duracao_media_ms_por_tipo'].items():
                w(f'  {k:<24} {v}')
        for tipo, campo in (('login_falha', 'ip'), ('falha_decifragem', 'usuario'), ('acesso_negado', 'usuario')):
            top = ae.top_origens(tipo, campo, 5, inc)
            if top:
                w(f'\nTop {campo} em {tipo}:')
                for k, n in top:
                    w(f'  {k:<24} {n}')

        if o['csv']:
            n = ae.exportar_csv(o['csv'], ae.eventos_para_dicts(inc))
            w(self.style.SUCCESS(f"\n{n} eventos exportados para {o['csv']}"))
        if o['features_csv']:
            linhas = ae.features_por_janela(o['janela'], inc)
            n = ae.exportar_csv(o['features_csv'], linhas)
            w(self.style.SUCCESS(f"{n} janelas de {o['janela']} min exportadas para {o['features_csv']}"))
